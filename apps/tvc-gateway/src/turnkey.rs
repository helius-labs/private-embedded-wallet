use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use bytes::Bytes;
use cadence_macros::statsd_count;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};
use turnkey_client::generated::external::options::v1::Pagination;
use turnkey_client::generated::services::coordinator::public::v1::{
    GetBootProofRequest, GetWalletAccountsRequest, GetWhoamiRequest,
};
use turnkey_client::{TurnkeyClient, TurnkeyClientError, TurnkeyP256ApiKey};

use crate::config::{TurnkeyApiKey, TurnkeyConfig};
use crate::error::ApiError;
use crate::limits::InFlightLimiter;
use crate::project::ProjectId;

const TURNKEY_TIMEOUT: Duration = Duration::from_secs(15);
/// Both Turnkey keys are shared by every project, so their call rate is too.
const MAX_CONCURRENT_TURNKEY_CALLS: usize = 32;
/// One project's share of those calls, so no project can take them all.
const MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT: u32 = 8;
const WALLET_ACCOUNTS_PAGE: &str = "100";
const BOOT_PROOF_CACHE_CAPACITY: usize = 256;
const OWNERSHIP_CACHE_CAPACITY: usize = 100_000;
/// A replica's ephemeral key, which signs its answers and names its Boot
/// Proof: 130 bytes, lowercase hex.
const EPHEMERAL_KEY_HEX_LEN: usize = 260;
const TURNKEY_PRIVATE_KEY_HEX_LEN: usize = 64;
const TURNKEY_PUBLIC_KEY_HEX_LEN: usize = 66;

/// The wallet a descriptor names, as the client claims it.
pub struct ClaimedWallet<'a> {
    pub organization_id: &'a str,
    pub wallet_id: &'a str,
    pub address: &'a str,
}

pub struct Turnkey {
    tvc_organization_id: String,
    boot_proofs: TurnkeyClient<TurnkeyP256ApiKey>,
    waas: TurnkeyClient<TurnkeyP256ApiKey>,
    boot_proof_cache: Mutex<HashMap<String, Bytes>>,
    ownership_ttl: Duration,
    sub_org_projects: Mutex<HashMap<String, (String, Instant)>>,
    calls: Semaphore,
    project_calls: InFlightLimiter,
}

/// One Turnkey call's slots: the project's own and a shared one.
type CallPermit<'a> = (OwnedSemaphorePermit, SemaphorePermit<'a>);

impl Turnkey {
    pub fn new(config: &TurnkeyConfig) -> anyhow::Result<Self> {
        Ok(Self {
            tvc_organization_id: config.tvc_organization_id.clone(),
            boot_proofs: client(
                &config.api_base_url,
                "boot_proof_api_key",
                &config.boot_proof_api_key,
            )?,
            waas: client(&config.api_base_url, "waas_api_key", &config.waas_api_key)?,
            boot_proof_cache: Mutex::new(HashMap::new()),
            ownership_ttl: Duration::from_secs(config.ownership_cache_secs),
            sub_org_projects: Mutex::new(HashMap::new()),
            calls: Semaphore::new(MAX_CONCURRENT_TURNKEY_CALLS),
            project_calls: project_calls(),
        })
    }

    /// The Boot Proof JSON for the replica whose ephemeral key is
    /// `ephemeral_key`, fetched for `project`. A replica's proof never changes.
    pub async fn boot_proof(
        &self,
        project: &ProjectId,
        ephemeral_key: &str,
    ) -> Result<Bytes, ApiError> {
        if !is_lower_hex(ephemeral_key, EPHEMERAL_KEY_HEX_LEN) {
            return Err(ApiError::InvalidEnclaveAnswer);
        }
        if let Some(cached) = self.cached_boot_proof(ephemeral_key) {
            statsd_count!("boot_proof.cache_hit", 1);
            return Ok(cached);
        }
        let _call = self.call_permit(project)?;
        let response = self
            .boot_proofs
            .get_boot_proof(GetBootProofRequest {
                organization_id: self.tvc_organization_id.clone(),
                ephemeral_key: ephemeral_key.to_owned(),
            })
            .await
            .map_err(|error| {
                turnkey_failure("get_boot_proof", &error, ApiError::BootProofUnavailable)
            })?;
        let boot_proof = response.boot_proof.ok_or(ApiError::BootProofUnavailable)?;
        let body = serde_json::to_vec(&boot_proof).map_err(|error| {
            tracing::error!(%error, "boot proof did not serialize");
            ApiError::BootProofUnavailable
        })?;
        let body = Bytes::from(body);
        self.cache_boot_proof(ephemeral_key, &body);
        Ok(body)
    }

    /// Refuses a wallet that is not in a sub-org of the caller's project, or
    /// whose account does not have the claimed address.
    pub async fn verify_ownership(
        &self,
        project: &ProjectId,
        wallet: &ClaimedWallet<'_>,
    ) -> Result<(), ApiError> {
        self.verify_sub_org_project(project, wallet.organization_id)
            .await?;
        let _call = self.call_permit(project)?;
        let accounts = self
            .waas
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: wallet.organization_id.to_owned(),
                wallet_id: Some(wallet.wallet_id.to_owned()),
                include_wallet_details: None,
                pagination_options: Some(Pagination {
                    limit: WALLET_ACCOUNTS_PAGE.to_owned(),
                    before: String::new(),
                    after: String::new(),
                }),
            })
            .await
            .map_err(|error| turnkey_failure("get_wallet_accounts", &error, NOT_OWNED))?;
        let owned = accounts.accounts.iter().any(|account| {
            account.wallet_id == wallet.wallet_id && account.address == wallet.address
        });
        if !owned {
            statsd_count!("ownership.rejected", 1, "reason" => "wallet");
            return Err(ApiError::WalletNotOwned);
        }
        Ok(())
    }

    /// Refuses a sub-org that is not named after the caller's project. Whoami
    /// through the parent key only resolves the parent's own sub-orgs.
    pub async fn verify_sub_org_project(
        &self,
        project: &ProjectId,
        organization_id: &str,
    ) -> Result<(), ApiError> {
        let name = match self.cached_sub_org_project(organization_id) {
            Some(name) => name,
            None => self.fetch_sub_org_project(project, organization_id).await?,
        };
        if name != project.as_str() {
            statsd_count!("ownership.rejected", 1, "reason" => "project");
            return Err(ApiError::SubOrganizationNotOwned);
        }
        Ok(())
    }

    async fn fetch_sub_org_project(
        &self,
        project: &ProjectId,
        organization_id: &str,
    ) -> Result<String, ApiError> {
        let _call = self.call_permit(project)?;
        let whoami = self
            .waas
            .get_whoami(GetWhoamiRequest {
                organization_id: organization_id.to_owned(),
            })
            .await
            .map_err(|error| turnkey_failure("get_whoami", &error, NOT_OWNED))?;
        let mut cache = self
            .sub_org_projects
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= OWNERSHIP_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(
            organization_id.to_owned(),
            (whoami.organization_name.clone(), Instant::now()),
        );
        Ok(whoami.organization_name)
    }

    /// Slots for one call for `project`: one of its own, then one of the
    /// shared ones. Neither waits.
    fn call_permit(&self, project: &ProjectId) -> Result<CallPermit<'_>, ApiError> {
        let own = self.project_calls.try_acquire(project)?;
        let shared = self.calls.try_acquire().map_err(|_| {
            statsd_count!("turnkey.concurrency_rejected", 1);
            ApiError::TooManyInFlight
        })?;
        Ok((own, shared))
    }

    fn cached_sub_org_project(&self, organization_id: &str) -> Option<String> {
        let cache = self
            .sub_org_projects
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (name, fetched_at) = cache.get(organization_id)?;
        (fetched_at.elapsed() < self.ownership_ttl).then(|| name.clone())
    }

    fn cached_boot_proof(&self, ephemeral_key: &str) -> Option<Bytes> {
        self.boot_proof_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(ephemeral_key)
            .cloned()
    }

    fn cache_boot_proof(&self, ephemeral_key: &str, body: &Bytes) {
        let mut cache = self
            .boot_proof_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= BOOT_PROOF_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(ephemeral_key.to_owned(), body.clone());
    }
}

fn project_calls() -> InFlightLimiter {
    InFlightLimiter::new(
        MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT,
        "turnkey.project_concurrency_rejected",
    )
}

/// `name` identifies the key in errors. The key is checked for shape first:
/// `TurnkeyP256ApiKey` panics on a private key of the wrong length.
fn client(
    base_url: &str,
    name: &str,
    key: &TurnkeyApiKey,
) -> anyhow::Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    anyhow::ensure!(
        is_lower_or_upper_hex(&key.private_key, TURNKEY_PRIVATE_KEY_HEX_LEN),
        "turnkey.{name}.private_key must be 32 bytes of hex"
    );
    anyhow::ensure!(
        is_lower_or_upper_hex(&key.public_key, TURNKEY_PUBLIC_KEY_HEX_LEN),
        "turnkey.{name}.public_key must be a 33-byte compressed P-256 key in hex"
    );
    let api_key = TurnkeyP256ApiKey::from_strings(&key.private_key, Some(&key.public_key))
        .map_err(|error| anyhow::anyhow!("turnkey.{name} is not a valid key pair: {error}"))?;
    Ok(TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .timeout(TURNKEY_TIMEOUT)
        .build()?)
}

const NOT_OWNED: ApiError = ApiError::TurnkeyRejected;

/// A 400, 403 or 404 is the caller's claim failing: `rejected` for the call.
/// A 401 is this gateway's key, a 429 Turnkey's limit, and anything else an
/// outage; all three are 424s.
fn turnkey_failure(call: &'static str, error: &TurnkeyClientError, rejected: ApiError) -> ApiError {
    let status = if let TurnkeyClientError::UnexpectedHttpStatus(status, _) = error {
        Some(*status)
    } else {
        None
    };
    let mapped = turnkey_status(status, rejected);
    if mapped.status() == StatusCode::FAILED_DEPENDENCY {
        let code = mapped.code();
        tracing::warn!(call, code, error = %error, "turnkey call failed");
        statsd_count!("turnkey.failed", 1, "call" => call, "code" => code);
    } else {
        statsd_count!("turnkey.rejected", 1, "call" => call);
    }
    mapped
}

const fn turnkey_status(status: Option<u16>, rejected: ApiError) -> ApiError {
    match status {
        Some(400 | 403 | 404) => rejected,
        Some(401) => ApiError::TurnkeyUnauthorized,
        Some(429) => ApiError::TurnkeyRateLimited,
        Some(_) | None => ApiError::TurnkeyUnavailable,
    }
}

#[inline]
fn is_lower_or_upper_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[inline]
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
impl Turnkey {
    pub(crate) fn for_tests(api_base_url: &str) -> Self {
        let key = || {
            TurnkeyP256ApiKey::from_strings("08".repeat(32), None)
                .expect("test turnkey key is invalid")
        };
        let build = || {
            TurnkeyClient::builder()
                .api_key(key())
                .base_url(api_base_url)
                .build()
                .expect("test turnkey client did not build")
        };
        Self {
            tvc_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            boot_proofs: build(),
            waas: build(),
            boot_proof_cache: Mutex::new(HashMap::new()),
            ownership_ttl: Duration::from_secs(600),
            sub_org_projects: Mutex::new(HashMap::new()),
            calls: Semaphore::new(MAX_CONCURRENT_TURNKEY_CALLS),
            project_calls: project_calls(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turnkey_statuses_split_between_the_callers_claim_and_upstream() {
        assert_eq!(turnkey_status(Some(403), NOT_OWNED), NOT_OWNED);
        assert_eq!(
            turnkey_status(Some(404), ApiError::BootProofUnavailable),
            ApiError::BootProofUnavailable
        );
        assert_eq!(
            turnkey_status(Some(401), NOT_OWNED),
            ApiError::TurnkeyUnauthorized
        );
        assert_eq!(
            turnkey_status(Some(429), NOT_OWNED),
            ApiError::TurnkeyRateLimited
        );
        assert_eq!(
            turnkey_status(Some(503), NOT_OWNED),
            ApiError::TurnkeyUnavailable
        );
        assert_eq!(
            turnkey_status(None, NOT_OWNED),
            ApiError::TurnkeyUnavailable
        );
    }

    fn turnkey_config(private_key: &str, public_key: &str) -> TurnkeyConfig {
        let key = TurnkeyApiKey {
            private_key: private_key.to_owned(),
            public_key: public_key.to_owned(),
        };
        TurnkeyConfig {
            api_base_url: "http://127.0.0.1:9".to_owned(),
            tvc_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            boot_proof_api_key: key.clone(),
            waas_api_key: key,
            ownership_cache_secs: 600,
        }
    }

    #[test]
    fn a_missing_or_malformed_turnkey_key_is_a_startup_error_not_a_panic() {
        for (private_key, public_key) in [
            ("", ""),
            ("08", "02"),
            (&*"zz".repeat(32), &*"02".repeat(33)),
            (&*"08".repeat(32), ""),
        ] {
            let error = Turnkey::new(&turnkey_config(private_key, public_key))
                .err()
                .expect("a malformed key was accepted");
            assert!(
                error.to_string().starts_with("turnkey.boot_proof_api_key"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_key_pair_that_does_not_match_is_refused() {
        let error = Turnkey::new(&turnkey_config(&"08".repeat(32), &"02".repeat(33)))
            .err()
            .expect("a mismatched key pair was accepted");
        assert!(
            error.to_string().contains("not a valid key pair"),
            "{error}"
        );
    }

    #[test]
    fn one_project_cannot_take_every_turnkey_call() {
        crate::metrics::init_for_tests();
        let turnkey = Turnkey::for_tests("http://127.0.0.1:9");
        let busy = ProjectId::for_tests("busy");
        let held: Vec<_> = (0..MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT)
            .map(|_| {
                turnkey
                    .call_permit(&busy)
                    .expect("within the project's share")
            })
            .collect();
        assert_eq!(
            turnkey.call_permit(&busy).err(),
            Some(ApiError::TooManyInFlight)
        );
        // The other projects share the rest, and only the rest.
        let rest = MAX_CONCURRENT_TURNKEY_CALLS - held.len();
        let others: Vec<_> = (0..rest)
            .map(|index| {
                let project = ProjectId::for_tests(&format!("other-{index}"));
                turnkey.call_permit(&project).expect("a shared slot")
            })
            .collect();
        assert_eq!(
            turnkey.call_permit(&ProjectId::for_tests("late")).err(),
            Some(ApiError::TooManyInFlight)
        );
        drop(others);
        assert!(turnkey.call_permit(&ProjectId::for_tests("late")).is_ok());
        drop(held);
        assert!(turnkey.call_permit(&busy).is_ok());
    }

    #[test]
    fn ephemeral_key_must_be_lower_hex_of_the_exact_length() {
        assert!(is_lower_hex(&"ab".repeat(130), EPHEMERAL_KEY_HEX_LEN));
        assert!(!is_lower_hex(&"AB".repeat(130), EPHEMERAL_KEY_HEX_LEN));
        assert!(!is_lower_hex(&"ab".repeat(129), EPHEMERAL_KEY_HEX_LEN));
    }
}
