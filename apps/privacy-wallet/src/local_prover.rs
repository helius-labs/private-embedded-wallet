//! A stand-in attested prover for the local testkit. It answers the
//! attestation route with a fixture Nitro document under a fixture root,
//! opens sealed requests, forwards them to a plaintext prover, and seals the
//! answers. The local enclave trusts its root and the testkit's prover policy
//! signer. Never linked into the enclave binary.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use axum::routing::get;
use axum::Router;
use serde_json::Value;
use spr_prover_tee::{
    seal_response, Anchors, FixtureProver, NitroFixture, SignedPolicyFile, ATTESTATION_PATH,
    HEADER_ENC, HEADER_VERSION, VERSION,
};
use zolana_tvc_protocol::encoding::decode_lower_hex_array;

use crate::local_dev::testkit_prover_keys;
use crate::operations::{sign_policy, NETWORK};

/// Serves the signed policy the local enclave accepts, for the local client.
pub const POLICY_PATH: &str = "/local/prover-policy";
const PROVE_SEGMENT: &str = "/prove/";
const POLICY_LIFETIME_SECS: u64 = 86_400;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);
const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);

pub struct LocalProver {
    prover: FixtureProver,
    /// Every fixture document and the trusted root are built at this instant,
    /// so the root the enclave pins is the one each document chains to.
    epoch_secs: u64,
    policy: SignedPolicyFile,
    upstream: String,
    client: reqwest::Client,
}

impl LocalProver {
    /// A prover forwarding to the plaintext prover at `upstream`.
    pub fn new(upstream: &str) -> Self {
        let (signer, ikm) = testkit_prover_keys();
        let prover = FixtureProver::from_ikm(&ikm);
        let epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs();
        let policy = sign_policy(
            &signer,
            NETWORK,
            NitroFixture::at([0; 32], epoch_secs).policy().clone(),
            epoch_secs,
            epoch_secs + POLICY_LIFETIME_SECS,
        );
        Self {
            prover,
            epoch_secs,
            policy,
            upstream: upstream.trim_end_matches('/').to_owned(),
            client: reqwest::Client::builder()
                .timeout(UPSTREAM_TIMEOUT)
                .build()
                .expect("HTTP client"),
        }
    }

    /// The root every document this prover signs chains to.
    pub fn anchors(&self) -> Anchors {
        self.fixture([0; 32]).anchors()
    }

    pub fn router(self) -> Router {
        Router::new()
            .route(ATTESTATION_PATH, get(attest))
            .route(POLICY_PATH, get(policy))
            .fallback(dispatch)
            .with_state(Arc::new(self))
    }

    fn fixture(&self, nonce: [u8; 32]) -> NitroFixture {
        NitroFixture::at(nonce, self.epoch_secs).with_hpke_public_key(self.prover.hpke_public_key())
    }

    /// Posts the opened request to the plaintext prover and returns its
    /// answer once it holds a proof.
    async fn forward(&self, key: &str, plaintext: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let failed = |status| (status, br#"{"code":"upstream_failed"}"#.to_vec());
        let response = self
            .client
            .post(format!("{}{PROVE_SEGMENT}{key}", self.upstream))
            .header("X-Sync", "true")
            .header(CONTENT_TYPE, "application/json")
            .body(plaintext)
            .send()
            .await;
        let Ok(response) = response else {
            return failed(StatusCode::BAD_GATEWAY);
        };
        let status = response.status();
        let Ok(body) = response.bytes().await else {
            return failed(StatusCode::BAD_GATEWAY);
        };
        let job = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|answer| {
                answer
                    .get("proof")
                    .is_none()
                    .then(|| {
                        answer
                            .get("jobId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten()
            });
        match job {
            Some(job) if status.is_success() => self.poll(key, &job).await,
            _ => (status, body.to_vec()),
        }
    }

    async fn poll(&self, key: &str, job: &str) -> (StatusCode, Vec<u8>) {
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        let mut interval = INITIAL_POLL_INTERVAL;
        while Instant::now() < deadline {
            tokio::time::sleep(interval).await;
            interval = (interval * 2).min(MAX_POLL_INTERVAL);
            let response = self
                .client
                .get(format!("{}{PROVE_SEGMENT}{key}/status", self.upstream))
                .query(&[("jobId", job)])
                .send()
                .await;
            let Ok(response) = response else { continue };
            if !response.status().is_success() {
                continue;
            }
            let Ok(status) = response.json::<Value>().await else {
                continue;
            };
            match status.get("status").and_then(Value::as_str) {
                Some("completed") => {
                    let proof = status.get("result").cloned().unwrap_or(status);
                    return (StatusCode::OK, proof.to_string().into_bytes());
                }
                Some("failed") => {
                    return (StatusCode::BAD_GATEWAY, status.to_string().into_bytes())
                }
                _ => {}
            }
        }
        (
            StatusCode::GATEWAY_TIMEOUT,
            br#"{"code":"upstream_timeout"}"#.to_vec(),
        )
    }
}

async fn attest(State(prover): State<Arc<LocalProver>>, uri: Uri) -> Response<Body> {
    let nonce = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("nonce="))
        .and_then(|nonce| decode_lower_hex_array::<32>(nonce).ok());
    match nonce {
        Some(nonce) => json(StatusCode::OK, &prover.fixture(nonce).attestation_json()),
        None => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"code": "invalid_nonce"}),
        ),
    }
}

async fn policy(State(prover): State<Arc<LocalProver>>) -> Response<Body> {
    json(
        StatusCode::OK,
        &serde_json::to_value(&prover.policy).expect("policy json"),
    )
}

async fn dispatch(
    State(prover): State<Arc<LocalProver>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    // The deployed prover accepts a gateway path prefix. Keep the local
    // attestation fixture reachable through the same opaque HTTP transport.
    if method == Method::GET && uri.path().ends_with(ATTESTATION_PATH) {
        return attest(State(prover), uri).await;
    }
    let key = uri
        .path()
        .rsplit_once(PROVE_SEGMENT)
        .map(|(_, key)| key.to_owned())
        .filter(|key| !key.is_empty() && !key.contains('/'));
    let (Some(key), true) = (key, method == Method::POST) else {
        return json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"code": "not_found"}),
        );
    };
    let enc = headers
        .get(HEADER_ENC)
        .and_then(|enc| enc.to_str().ok())
        .and_then(|enc| hex::decode(enc).ok());
    let versioned = headers
        .get(HEADER_VERSION)
        .is_some_and(|version| version.as_bytes() == VERSION.as_bytes());
    let (Some(enc), true) = (enc, versioned) else {
        return json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"code": "tee_request_malformed"}),
        );
    };
    let request_uri = uri
        .path_and_query()
        .map_or(uri.path(), |target| target.as_str());
    let Ok(opened) = prover.prover.open("POST", request_uri, &enc, &body) else {
        return json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"code": "tee_decryption_failed"}),
        );
    };
    let (status, answer) = prover.forward(&key, opened.plaintext).await;
    match seal_response(&opened.response_key, status.as_u16(), &answer) {
        Ok(sealed) => Response::builder()
            .status(StatusCode::OK)
            .header(HEADER_VERSION, VERSION)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(sealed))
            .expect("response"),
        Err(_) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            &serde_json::json!({"code": "seal_failed"}),
        ),
    }
}

fn json(status: StatusCode, body: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn attestation_preserves_its_contract_under_a_gateway_prefix() {
        for prefix in ["", "/v1/proxy"] {
            let prover = LocalProver::new("http://127.0.0.1:1");
            let expected_key = hex::encode(prover.prover.hpke_public_key());
            let request = axum::http::Request::builder()
                .uri(format!(
                    "{prefix}{ATTESTATION_PATH}?nonce={}",
                    "00".repeat(32)
                ))
                .body(Body::empty())
                .unwrap();
            let response = prover.router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let attestation: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(attestation["hpke_public_key"], expected_key);
            assert_eq!(attestation["platform"], "aws-nitro");
        }
    }
}
