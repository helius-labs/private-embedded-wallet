use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::{HeaderValue, StatusCode};
use bytes::Bytes;
use cadence_macros::statsd_count;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::project::ProjectId;
use crate::upstream::Forwarded;

const KEY_PREFIX: &str = "tvc-gateway:replay:";
const REDIS_TIMEOUT: Duration = Duration::from_millis(500);
const RUNNING: &str = "running";
/// The largest answer the ledger keeps. A larger one is not kept, and a resend
/// runs again: only `Decrypt`, `Derive`, `TransactionKeys` and `Prove` answer
/// this much, and running them twice gives the same answer or a new sealing
/// of the same proof. A `Bootstrap` answer, which must not run twice, is a few
/// kilobytes.
pub const MAX_KEPT_ANSWER_BYTES: usize = 64 * 1024;

/// What the enclave did with an operation: its answer, or the failure that
/// left it unknown.
pub type Outcome = Result<Forwarded, ApiError>;

/// The digest of a project and a ciphertext it claimed. Project IDs hold no
/// NUL, so the pair is unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key([u8; 32]);

impl Key {
    fn of(project: &ProjectId, ciphertext: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(project.as_str().as_bytes());
        digest.update([0]);
        digest.update(ciphertext);
        Self(digest.finalize().into())
    }
}

#[derive(Debug)]
pub enum Claim {
    /// The project sent no request with the ciphertext within the window.
    /// This one now holds it, and must record its outcome or release it.
    New(Key),
    /// A request from the project sent it, and this was the outcome.
    Answered(Outcome),
}

/// The first outcome of each project's `/operations` ciphertext within the
/// window, so a resent operation gets that outcome instead of running twice.
/// Projects do not share entries, so none can claim another's ciphertext
/// first.
pub enum ReplayLedger {
    Local(LocalLedger),
    Shared(SharedLedger),
}

impl ReplayLedger {
    pub async fn connect(
        window: Duration,
        max_entries: usize,
        redis_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        let Some(url) = redis_url else {
            return Ok(Self::Local(LocalLedger::new(window, max_entries)));
        };
        let connection = ConnectionManager::new(redis::Client::open(url)?).await?;
        Ok(Self::Shared(SharedLedger {
            connection,
            window_secs: window.as_secs().max(1),
        }))
    }

    /// Refuses a ciphertext the project's earlier request is still running.
    pub async fn claim(&self, project: &ProjectId, ciphertext: &[u8]) -> Result<Claim, ApiError> {
        let key = Key::of(project, ciphertext);
        let claim = match self {
            Self::Local(ledger) => ledger.claim(key, Instant::now()),
            Self::Shared(ledger) => ledger.claim(key).await,
        };
        match &claim {
            Err(ApiError::OperationInProgress) => {
                statsd_count!("operations.in_progress", 1);
            }
            Ok(Claim::Answered(_)) => {
                statsd_count!("operations.replayed", 1);
            }
            _ => {}
        }
        claim
    }

    /// Records the outcome of a claimed ciphertext. If that fails, the claim
    /// stands until the window ends, and a resend gets `OperationInProgress`.
    /// An answer above [`MAX_KEPT_ANSWER_BYTES`] releases the claim instead.
    pub async fn record(&self, key: Key, outcome: &Outcome) {
        if outcome
            .as_ref()
            .is_ok_and(|answer| answer.body.len() > MAX_KEPT_ANSWER_BYTES)
        {
            statsd_count!("operations.answer_not_kept", 1);
            return self.release(key).await;
        }
        match self {
            Self::Local(ledger) => ledger.record(key, outcome),
            Self::Shared(ledger) => ledger.record(key, outcome).await,
        }
    }

    /// Gives up a claim whose request never reached the enclave.
    pub async fn release(&self, key: Key) {
        match self {
            Self::Local(ledger) => ledger.release(key),
            Self::Shared(ledger) => ledger.release(key).await,
        }
    }
}

/// An outcome as the shared ledger stores it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Record {
    Answered {
        status: u16,
        content_type: String,
        body: String,
    },
    Failed {
        code: String,
    },
}

impl Record {
    fn new(outcome: &Outcome) -> Option<Self> {
        Some(match outcome {
            Ok(forwarded) => Self::Answered {
                status: forwarded.status.as_u16(),
                content_type: forwarded.content_type.to_str().ok()?.to_owned(),
                body: String::from_utf8(forwarded.body.to_vec()).ok()?,
            },
            Err(error) => Self::Failed {
                code: error.code().to_owned(),
            },
        })
    }

    fn outcome(self) -> Option<Outcome> {
        Some(match self {
            Self::Answered {
                status,
                content_type,
                body,
            } => Ok(Forwarded {
                status: StatusCode::from_u16(status).ok()?,
                content_type: HeaderValue::try_from(content_type).ok()?,
                body: Bytes::from(body),
            }),
            Self::Failed { code } => Err(code.parse().ok()?),
        })
    }
}

/// Every gateway task shares the ledger through Redis. Claiming is one
/// `SET key running NX GET EX window`, so exactly one task runs a ciphertext
/// and the others read its record; an unreachable Redis refuses the request.
pub struct SharedLedger {
    connection: ConnectionManager,
    window_secs: u64,
}

impl SharedLedger {
    fn redis_key(key: Key) -> String {
        format!("{KEY_PREFIX}{}", hex::encode(key.0))
    }

    async fn query<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> Result<T, ApiError> {
        let mut connection = self.connection.clone();
        let unavailable = |reason: &str| {
            tracing::warn!(reason, "replay ledger unavailable");
            statsd_count!("enclave.replay_guard_unavailable", 1);
            ApiError::ReplayGuardUnavailable
        };
        match tokio::time::timeout(REDIS_TIMEOUT, command.query_async(&mut connection)).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(error)) => Err(unavailable(&error.to_string())),
            Err(_) => Err(unavailable("timed out")),
        }
    }

    async fn claim(&self, key: Key) -> Result<Claim, ApiError> {
        let mut claim = redis::cmd("SET");
        claim
            .arg(Self::redis_key(key))
            .arg(RUNNING)
            .arg("NX")
            .arg("GET")
            .arg("EX")
            .arg(self.window_secs);
        let Some(held) = self.query::<Option<String>>(&claim).await? else {
            return Ok(Claim::New(key));
        };
        if held == RUNNING {
            return Err(ApiError::OperationInProgress);
        }
        let record: Record = serde_json::from_str(&held).map_err(|error| {
            tracing::warn!(%error, "replay record is malformed");
            ApiError::ReplayGuardUnavailable
        })?;
        record
            .outcome()
            .map(Claim::Answered)
            .ok_or(ApiError::ReplayGuardUnavailable)
    }

    async fn record(&self, key: Key, outcome: &Outcome) {
        let Some(record) = Record::new(outcome).and_then(|r| serde_json::to_string(&r).ok()) else {
            tracing::warn!("operation outcome is not recordable");
            return;
        };
        let mut set = redis::cmd("SET");
        set.arg(Self::redis_key(key))
            .arg(record)
            .arg("XX")
            .arg("EX")
            .arg(self.window_secs);
        let _ = self.query::<Option<String>>(&set).await;
    }

    async fn release(&self, key: Key) {
        let mut delete = redis::cmd("DEL");
        delete.arg(Self::redis_key(key));
        let _ = self.query::<u64>(&delete).await;
    }
}

enum Entry {
    Running,
    Answered(Outcome),
}

/// The ledger of one process. Two generations rotate, so an outcome is
/// remembered for one to two windows.
pub struct LocalLedger {
    window: Duration,
    max_entries: usize,
    state: Mutex<Generations>,
}

struct Generations {
    maps: [HashMap<Key, Entry>; 2],
    current: usize,
    rotated_at: Instant,
}

impl Generations {
    fn rotate(&mut self, now: Instant) {
        self.current ^= 1;
        self.maps[self.current].clear();
        self.rotated_at = now;
    }

    fn get_mut(&mut self, key: Key) -> Option<&mut Entry> {
        let [first, second] = &mut self.maps;
        first.get_mut(&key).or_else(|| second.get_mut(&key))
    }
}

impl LocalLedger {
    pub fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            window,
            max_entries,
            state: Mutex::new(Generations {
                maps: [HashMap::new(), HashMap::new()],
                current: 0,
                rotated_at: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Generations> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn claim(&self, key: Key, now: Instant) -> Result<Claim, ApiError> {
        let mut state = self.lock();
        let expired = now.saturating_duration_since(state.rotated_at) >= self.window;
        if expired || state.maps[state.current].len() >= self.max_entries {
            if !expired {
                statsd_count!("enclave.replay_guard_early_rotation", 1);
            }
            state.rotate(now);
        }
        match state.get_mut(key) {
            None => {
                let current = state.current;
                state.maps[current].insert(key, Entry::Running);
                Ok(Claim::New(key))
            }
            Some(Entry::Running) => Err(ApiError::OperationInProgress),
            Some(Entry::Answered(outcome)) => Ok(Claim::Answered(outcome.clone())),
        }
    }

    fn record(&self, key: Key, outcome: &Outcome) {
        if let Some(entry) = self.lock().get_mut(key) {
            *entry = Entry::Answered(outcome.clone());
        }
    }

    fn release(&self, key: Key) {
        for map in &mut self.lock().maps {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn answer(body: &str) -> Outcome {
        Ok(Forwarded {
            status: StatusCode::OK,
            content_type: HeaderValue::from_static("application/json"),
            body: Bytes::from(body.to_owned()),
        })
    }

    fn body(claim: Result<Claim, ApiError>) -> Result<String, ApiError> {
        match claim? {
            Claim::Answered(outcome) => {
                outcome.map(|forwarded| String::from_utf8_lossy(&forwarded.body).into_owned())
            }
            Claim::New(_) => Ok("new".to_owned()),
        }
    }

    /// Exercises one ledger the way two gateway tasks would.
    async fn a_resend_gets_the_first_outcome(ledger: &ReplayLedger) {
        let (project, other) = (ProjectId::for_tests("a"), ProjectId::for_tests("b"));
        let Ok(Claim::New(key)) = ledger.claim(&project, b"ciphertext").await else {
            panic!("the first claim is new");
        };
        assert_eq!(
            body(ledger.claim(&project, b"ciphertext").await),
            Err(ApiError::OperationInProgress)
        );
        ledger.record(key, &answer("first")).await;
        assert_eq!(
            body(ledger.claim(&project, b"ciphertext").await),
            Ok("first".to_owned())
        );

        // Another project's request with the same ciphertext is its own: it
        // neither sees nor takes the first project's entry.
        let Ok(Claim::New(theirs)) = ledger.claim(&other, b"ciphertext").await else {
            panic!("another project's claim is new");
        };
        assert_ne!(theirs, key);
        ledger.record(theirs, &answer("theirs")).await;
        assert_eq!(
            body(ledger.claim(&project, b"ciphertext").await),
            Ok("first".to_owned())
        );
        assert_eq!(
            body(ledger.claim(&other, b"ciphertext").await),
            Ok("theirs".to_owned())
        );

        let Ok(Claim::New(failed)) = ledger.claim(&project, b"failed").await else {
            panic!("the first claim is new");
        };
        ledger
            .record(failed, &Err(ApiError::EnclaveUnavailable))
            .await;
        assert_eq!(
            body(ledger.claim(&project, b"failed").await),
            Err(ApiError::EnclaveUnavailable)
        );

        let Ok(Claim::New(released)) = ledger.claim(&project, b"released").await else {
            panic!("the first claim is new");
        };
        ledger.release(released).await;
        assert_eq!(
            body(ledger.claim(&project, b"released").await),
            Ok("new".to_owned())
        );

        // An answer at the cap is kept; a larger one releases its claim.
        let largest = "x".repeat(MAX_KEPT_ANSWER_BYTES);
        let Ok(Claim::New(kept)) = ledger.claim(&project, b"largest").await else {
            panic!("the first claim is new");
        };
        ledger.record(kept, &answer(&largest)).await;
        assert_eq!(body(ledger.claim(&project, b"largest").await), Ok(largest));
        let Ok(Claim::New(dropped)) = ledger.claim(&project, b"too large").await else {
            panic!("the first claim is new");
        };
        ledger
            .record(dropped, &answer(&"x".repeat(MAX_KEPT_ANSWER_BYTES + 1)))
            .await;
        assert_eq!(
            body(ledger.claim(&project, b"too large").await),
            Ok("new".to_owned())
        );
    }

    #[tokio::test]
    async fn a_local_ledger_returns_the_first_outcome_to_a_resend() {
        crate::metrics::init_for_tests();
        let ledger = ReplayLedger::Local(LocalLedger::new(Duration::from_secs(60), 16));
        a_resend_gets_the_first_outcome(&ledger).await;
    }

    #[tokio::test]
    async fn a_shared_ledger_returns_the_first_outcome_to_a_resend() {
        crate::metrics::init_for_tests();
        let url = fake_redis(true).await;
        a_resend_gets_the_first_outcome(&shared(&url).await).await;
    }

    #[test]
    fn a_local_ledger_remembers_across_one_rotation_then_forgets() {
        crate::metrics::init_for_tests();
        let ledger = LocalLedger::new(Duration::from_secs(60), 16);
        let now = Instant::now();
        let key = Key([1; 32]);
        assert!(matches!(ledger.claim(key, now), Ok(Claim::New(_))));
        assert!(matches!(
            ledger.claim(key, now + Duration::from_secs(61)),
            Err(ApiError::OperationInProgress)
        ));
        assert!(matches!(
            ledger.claim(Key([2; 32]), now + Duration::from_secs(122)),
            Ok(Claim::New(_))
        ));
        assert!(matches!(
            ledger.claim(key, now + Duration::from_secs(123)),
            Ok(Claim::New(_))
        ));
    }

    #[tokio::test]
    async fn an_unresponsive_redis_refuses_the_request() {
        crate::metrics::init_for_tests();
        let ledger = shared(&fake_redis(false).await).await;
        assert_eq!(
            body(
                ledger
                    .claim(&ProjectId::for_tests("a"), b"ciphertext")
                    .await
            ),
            Err(ApiError::ReplayGuardUnavailable)
        );
    }

    async fn shared(url: &str) -> ReplayLedger {
        ReplayLedger::connect(Duration::from_secs(360), 16, Some(url))
            .await
            .expect("the shared ledger connects")
    }

    /// A Redis stand-in on loopback that keeps `SET` (with `NX`, `XX` and
    /// `GET`), `DEL` and nothing else in memory, ignoring expiry. With
    /// `answering` false it never answers a `SET`.
    async fn fake_redis(answering: bool) -> String {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake redis binds");
        let addr = listener.local_addr().expect("fake redis has an address");
        let keys = Arc::new(Mutex::new(HashMap::<String, String>::new()));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_fake_redis(stream, Arc::clone(&keys), answering));
            }
        });
        format!("redis://{addr}/2")
    }

    fn bulk(value: Option<&String>) -> String {
        value.map_or_else(
            || "$-1\r\n".to_owned(),
            |v| format!("${}\r\n{v}\r\n", v.len()),
        )
    }

    async fn serve_fake_redis(
        stream: tokio::net::TcpStream,
        keys: Arc<Mutex<HashMap<String, String>>>,
        answering: bool,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let count: usize = line.trim().trim_start_matches('*').parse().unwrap_or(0);
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                line.clear();
                let _ = reader.read_line(&mut line).await;
                let len: usize = line.trim().trim_start_matches('$').parse().unwrap_or(0);
                let mut arg = vec![0u8; len + 2];
                let _ = reader.read_exact(&mut arg).await;
                args.push(String::from_utf8_lossy(&arg[..len]).into_owned());
            }
            let has = |flag: &str| args.iter().any(|arg| arg.eq_ignore_ascii_case(flag));
            let name = args.first().map(|name| name.to_ascii_uppercase());
            let reply = match (name.as_deref(), args.get(1), args.get(2)) {
                (Some("SET"), _, _) if !answering => continue,
                (Some("SET"), Some(key), Some(value)) => {
                    let mut keys = keys.lock().unwrap_or_else(PoisonError::into_inner);
                    let held = keys.get(key).cloned();
                    let write = (!has("NX") || held.is_none()) && (!has("XX") || held.is_some());
                    if write {
                        keys.insert(key.clone(), value.clone());
                    }
                    match (has("GET"), write) {
                        (true, _) => bulk(held.as_ref()),
                        (false, true) => "+OK\r\n".to_owned(),
                        (false, false) => "$-1\r\n".to_owned(),
                    }
                }
                (Some("DEL"), Some(key), _) => {
                    let removed = keys
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(key);
                    format!(":{}\r\n", u8::from(removed.is_some()))
                }
                _ => "+OK\r\n".to_owned(),
            };
            if write.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }
}
