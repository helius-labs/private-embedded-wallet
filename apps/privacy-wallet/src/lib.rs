//! Privacy-wallet TVC application.
//!
//! The enclave holds the wallet's privacy roles (nullifier and viewing keys)
//! and answers five encrypted operations: bootstrap the identity, decrypt
//! ciphertexts, derive nullifiers and merge values, mint per-transaction
//! viewing keys, and complete a prover request sealed to an attested prover.
//! The client does
//! everything else with the Zolana SDK, including signing. Boot Proof
//! verification is the relying party's job.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::Router;
use p256::ecdsa::Signature;
use qos_core::handles::Handles;
use qos_core::{EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE};
use qos_p256::P256Pair;
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES, MAX_ENCRYPTED_RESPONSE_BYTES, TVC_APP_PROOF_SCHEME,
    TVC_APP_PROOF_TYPE, TVC_QOS_PING_PROOF_TYPE,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_qos_ping_challenge, parse_qos_ping_request, AppProof, Environment, HealthResponse,
    HealthStatus, QosPingResponse, ServiceInfo,
};

use crate::http::PublicError;

mod custody;
mod http;
mod operations;
mod turnkey;

#[cfg(feature = "local-dev")]
mod local_dev;
#[cfg(feature = "local-dev")]
mod local_prover;
#[cfg(feature = "local-dev")]
pub use local_dev::{local_testkit_qos_seeds, local_unattested_state, LocalProverTrust};
#[cfg(feature = "local-dev")]
pub use local_prover::{LocalProver, POLICY_PATH};

pub use operations::{NETWORK, OPERATIONS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub security_domain_id: [u8; 32],
    pub release_id: String,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
}

impl DiscoveryConfig {
    /// What `/v1/info` advertises for this release running under these QOS
    /// keys.
    fn service_info(
        self,
        manifest_digest: [u8; 32],
        executable_digest: [u8; 32],
        quorum: &P256Pair,
        ephemeral: &P256Pair,
    ) -> ServiceInfo {
        let ephemeral_public_key = ephemeral.public_key().to_bytes();
        ServiceInfo {
            version: API_VERSION,
            environment: Environment::Development,
            security_domain_id: self.security_domain_id,
            release_id: self.release_id,
            manifest_digest,
            executable_digest,
            quorum_public_key: quorum.public_key().to_bytes(),
            quorum_key_id: self.quorum_key_id,
            quorum_key_epoch: self.quorum_key_epoch,
            ephemeral_public_key: ephemeral_public_key.clone(),
            supported_operations: OPERATIONS.to_vec(),
            max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES,
            max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES,
            proof_type: TVC_APP_PROOF_TYPE.to_owned(),
            boot_proof_lookup_key: ephemeral_public_key,
        }
    }
}

/// Everything a running enclave needs to answer an operation.
struct Runtime {
    ephemeral: Arc<P256Pair>,
    quorum: Arc<P256Pair>,
    custody: Arc<dyn custody::Custody>,
    /// Signs wallet descriptors. Only the public half is present in the image.
    provisioning_public: [u8; 65],
    /// Signs wallet grants. Only the public half is present in the image.
    grant_public: [u8; 65],
    /// The provers a completed witness may be sealed to.
    prover: operations::ProverTrust,
}

#[derive(Clone)]
pub struct AppState {
    info: Arc<ServiceInfo>,
    runtime: Arc<Runtime>,
}

impl AppState {
    pub fn ready(info: ServiceInfo, ephemeral: P256Pair, quorum: P256Pair) -> Self {
        let quorum = Arc::new(quorum);
        Self {
            info: Arc::new(info),
            runtime: Arc::new(Runtime {
                ephemeral: Arc::new(ephemeral),
                custody: Arc::new(custody::TurnkeyCustody::new(Arc::clone(&quorum))),
                quorum,
                provisioning_public: operations::PROVISIONING_PUBLIC,
                grant_public: operations::GRANT_PUBLIC,
                prover: operations::ProverTrust::image(),
            }),
        }
    }
}

/// Load QOS-owned state from the canonical paths and bind discovery to the
/// approved manifest. Failures are deliberately free of key material.
pub fn load_qos_state(config: DiscoveryConfig) -> io::Result<AppState> {
    if config.release_id.is_empty() || config.quorum_key_id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "release and quorum key identifiers must not be empty",
        ));
    }

    let handles = Handles::new(
        EPHEMERAL_KEY_FILE.to_owned(),
        QUORUM_FILE.to_owned(),
        MANIFEST_FILE.to_owned(),
        PIVOT_FILE.to_owned(),
    );
    let ephemeral = handles
        .get_ephemeral_key()
        .map_err(|_| io::Error::other("failed to load QOS ephemeral key"))?;
    let quorum = handles
        .get_quorum_key()
        .map_err(|_| io::Error::other("failed to load QOS quorum key"))?;
    let envelope = handles
        .get_manifest_envelope()
        .map_err(|_| io::Error::other("failed to load QOS manifest"))?;

    let manifest_digest = envelope.manifest_hash();
    let executable_digest = *envelope.pivot_hash();
    if envelope.manifest().namespace().quorum_key != quorum.public_key().to_bytes() {
        return Err(io::Error::other(
            "QOS quorum key does not match the approved manifest",
        ));
    }

    let info = config.service_info(manifest_digest, executable_digest, &quorum, &ephemeral);
    Ok(AppState::ready(info, ephemeral, quorum))
}

pub fn router(state: AppState) -> Router {
    Router::new().fallback(dispatch).with_state(state)
}

/// `/v1/ping` and `/v1/operations` take JSON posts. `/health` is process
/// readiness only and MUST NOT include release, key, or deployment
/// identifiers; `/v1/info` is discovery data, not a trust root.
async fn dispatch(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body_limit = usize::try_from(
        state
            .info
            .max_encrypted_request_bytes
            .min(MAX_ENCRYPTED_REQUEST_BYTES),
    )
    .unwrap_or(usize::MAX);
    let Ok(body) = to_bytes(body, body_limit).await else {
        return PublicError::RequestTooLarge.into_response();
    };

    match (parts.method.as_str(), parts.uri.path()) {
        ("POST", "/v1/ping" | "/v1/operations") if !has_json_content_type(&parts.headers) => {
            PublicError::InvalidRequest.into_response()
        }
        ("POST", "/v1/ping") => handle_ping(&state, &body),
        ("POST", "/v1/operations") => operations::handle(&state, &body).await,
        ("GET", "/health") => match jcs_serialize(&HealthResponse {
            status: HealthStatus::Healthy,
        }) {
            Ok(body) => http::ok(body),
            Err(_) => PublicError::Unavailable.into_response(),
        },
        ("GET", "/v1/info") => match jcs_serialize(&*state.info) {
            Ok(body) => http::ok(body),
            Err(_) => PublicError::InvalidRequest.into_response(),
        },
        (_, "/v1/ping" | "/v1/operations" | "/health" | "/v1/info") => {
            PublicError::MethodNotAllowed.into_response()
        }
        _ => PublicError::NotFound.into_response(),
    }
}

fn has_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim() == "application/json")
}

fn handle_ping(state: &AppState, body: &[u8]) -> Response<Body> {
    let runtime = &state.runtime;
    let invalid = || PublicError::InvalidRequest.into_response();
    let Ok(body) = std::str::from_utf8(body) else {
        return invalid();
    };
    let Ok(request) = parse_qos_ping_request(body) else {
        return invalid();
    };
    if request.version != API_VERSION {
        return invalid();
    }
    let Ok(plaintext) = runtime.quorum.decrypt(&request.encrypted_challenge) else {
        return invalid();
    };
    let Ok(proof_payload) = std::str::from_utf8(&plaintext) else {
        return invalid();
    };
    let Ok(challenge) = parse_qos_ping_challenge(proof_payload) else {
        return invalid();
    };
    if challenge.version != API_VERSION
        || challenge.r#type != TVC_QOS_PING_PROOF_TYPE
        || !is_rfc8785(proof_payload)
    {
        return invalid();
    }

    let Ok(signature) = sign_ephemeral_low_s(&runtime.ephemeral, proof_payload.as_bytes()) else {
        return PublicError::Unavailable.into_response();
    };
    let response = QosPingResponse {
        version: API_VERSION,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: runtime.ephemeral.public_key().to_bytes(),
            proof_payload: proof_payload.to_owned(),
            signature,
        },
    };
    match jcs_serialize(&response) {
        Ok(body) => http::ok(body),
        Err(_) => PublicError::Unavailable.into_response(),
    }
}

fn sign_ephemeral_low_s(ephemeral: &P256Pair, message: &[u8]) -> Result<Vec<u8>, ()> {
    let raw = ephemeral.sign(message).map_err(|_| ())?;
    let signature = Signature::from_slice(&raw).map_err(|_| ())?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    Ok(normalized.to_bytes().to_vec())
}

/// Resolves on SIGINT or SIGTERM, the signals QOS and a shell send.
pub async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use zeroize::Zeroizing;
    use zolana_tvc_protocol::constants::{QOS_P256_PUBLIC_LEN, RAW_P256_SIGNATURE_LEN};
    use zolana_tvc_protocol::crypto::{verify_p256_message, QosP256Public};
    use zolana_tvc_protocol::encoding::{jcs_serialize, parse_strict_json};
    use zolana_tvc_protocol::types::{QosPingChallenge, QosPingRequest, QosPingResponse};

    use super::*;

    fn info(quorum: &P256Pair, ephemeral: &P256Pair) -> ServiceInfo {
        let config = DiscoveryConfig {
            security_domain_id: [0x11; 32],
            release_id: "tvc-pet-test".to_owned(),
            quorum_key_id: "quorum-test".to_owned(),
            quorum_key_epoch: 1,
        };
        config.service_info([0x22; 32], [0x33; 32], quorum, ephemeral)
    }

    async fn response_body(response: Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn health_is_exact() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let response = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ))
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(response_body(response).await, r#"{"status":"Healthy"}"#);
    }

    #[tokio::test]
    async fn info_is_untrusted_discovery_bound_to_runtime_public_keys() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let expected = info(&quorum, &ephemeral);
        let response = router(AppState::ready(expected.clone(), ephemeral, quorum))
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let actual: ServiceInfo = parse_strict_json(&response_body(response).await).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.boot_proof_lookup_key, actual.ephemeral_public_key);
    }

    #[tokio::test]
    async fn ping_decrypts_with_quorum_and_signs_exact_utf8_with_ephemeral() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let quorum_public = quorum.public_key();
        let ephemeral_public = ephemeral.public_key();
        let proof_payload = jcs_serialize(&QosPingChallenge {
            r#type: TVC_QOS_PING_PROOF_TYPE.to_owned(),
            version: API_VERSION,
            challenge: [0x44; 32],
        })
        .unwrap();
        let encrypted_challenge = quorum_public.encrypt(proof_payload.as_bytes()).unwrap();
        let request_body = jcs_serialize(&QosPingRequest {
            version: API_VERSION,
            encrypted_challenge,
        })
        .unwrap();
        let response = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ))
        .oneshot(
            Request::post("/v1/ping")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response: QosPingResponse = parse_strict_json(&response_body(response).await).unwrap();
        let proof = response.tvc_app_proof;
        assert_eq!(proof.scheme, TVC_APP_PROOF_SCHEME);
        assert_eq!(proof.public_key, ephemeral_public.to_bytes());
        assert_eq!(proof.public_key.len(), QOS_P256_PUBLIC_LEN);
        assert_eq!(proof.proof_payload.as_bytes(), proof_payload.as_bytes());
        assert_eq!(proof.signature.len(), RAW_P256_SIGNATURE_LEN);
        ephemeral_public
            .verify(proof.proof_payload.as_bytes(), &proof.signature)
            .unwrap();
        assert!(quorum_public
            .verify(proof.proof_payload.as_bytes(), &proof.signature)
            .is_err());
        let parsed = QosP256Public::from_bytes(&proof.public_key).unwrap();
        verify_p256_message(
            &parsed.signing,
            proof.proof_payload.as_bytes(),
            &proof.signature,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn ping_rejects_ephemeral_encryption_and_noncanonical_plaintext_generically() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let noncanonical = format!(
            r#"{{"version":1,"type":"{TVC_QOS_PING_PROOF_TYPE}","challenge":"{}"}}"#,
            "55".repeat(32)
        );
        let cases = [
            ephemeral
                .public_key()
                .encrypt(b"not for the quorum")
                .unwrap(),
            quorum
                .public_key()
                .encrypt(noncanonical.as_bytes())
                .unwrap(),
        ];
        let app = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ));

        for encrypted_challenge in cases {
            let body = jcs_serialize(&QosPingRequest {
                version: API_VERSION,
                encrypted_challenge,
            })
            .unwrap();
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/ping")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_body(response).await,
                r#"{"error":"InvalidRequest"}"#
            );
        }
    }

    #[tokio::test]
    async fn ping_rejects_wrong_method_and_oversized_body() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let app = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ));

        let response = app
            .clone()
            .oneshot(Request::get("/v1/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let response = app
            .oneshot(
                Request::post("/v1/ping")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![
                        0u8;
                        MAX_ENCRYPTED_REQUEST_BYTES as usize + 1
                    ]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn every_other_request_gets_a_generic_json_error() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let app = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ));
        let request = |method: &str, path: &str, content_type: &str, body: Vec<u8>| {
            let mut request = Request::builder().method(method).uri(path);
            if !content_type.is_empty() {
                request = request.header(CONTENT_TYPE, content_type);
            }
            request.body(Body::from(body)).unwrap()
        };
        let json = "application/json";
        let oversized = vec![0u8; MAX_ENCRYPTED_REQUEST_BYTES as usize + 1];
        let not_allowed = (StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed");
        let not_found = (StatusCode::NOT_FOUND, "NotFound");
        let invalid = (StatusCode::BAD_REQUEST, "InvalidRequest");
        let cases = [
            (
                request("GET", "/v1/operations", "", Vec::new()),
                not_allowed,
            ),
            (request("PUT", "/v1/ping", json, Vec::new()), not_allowed),
            (request("POST", "/health", json, Vec::new()), not_allowed),
            (request("DELETE", "/v1/info", "", Vec::new()), not_allowed),
            (request("GET", "/v1/unknown", "", Vec::new()), not_found),
            (request("POST", "/", json, Vec::new()), not_found),
            (
                request("POST", "/v1/operations", "text/plain", Vec::new()),
                invalid,
            ),
            (request("POST", "/v1/ping", "", Vec::new()), invalid),
            (
                request(
                    "POST",
                    "/v1/operations",
                    "application/json; charset=utf-8",
                    b"{}".to_vec(),
                ),
                invalid,
            ),
            (
                request("GET", "/health", "", oversized),
                (StatusCode::PAYLOAD_TOO_LARGE, "RequestTooLarge"),
            ),
        ];
        for (request, (status, error)) in cases {
            let target = format!("{} {}", request.method(), request.uri());
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status, "{target}");
            assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
            assert_eq!(
                response_body(response).await,
                format!(r#"{{"error":"{error}"}}"#),
                "{target}"
            );
        }
    }

    #[test]
    fn qos_signatures_are_normalized_to_low_s_for_the_wire() {
        let message = b"zolana tvc low-s interop";
        for seed_byte in 0u8..=u8::MAX {
            let pair = P256Pair::from_master_seed(&Zeroizing::new([seed_byte; 32])).unwrap();
            let raw = pair.sign(message).unwrap();
            let raw = Signature::from_slice(&raw).unwrap();
            if raw.normalize_s().is_some() {
                let normalized = sign_ephemeral_low_s(&pair, message).unwrap();
                let normalized = Signature::from_slice(&normalized).unwrap();
                assert!(normalized.normalize_s().is_none());
                pair.public_key()
                    .verify(message, &normalized.to_bytes())
                    .unwrap();
                return;
            }
        }
        panic!("fixed QOS seed corpus did not produce a high-S signature");
    }
}
