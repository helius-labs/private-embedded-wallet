//! The routes every application serves around its own operations.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::Router;
use qos_core::handles::Handles;
use qos_core::{EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE};
use qos_p256::P256Pair;
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES, TVC_APP_PROOF_SCHEME, TVC_QOS_PING_PROOF_TYPE,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_qos_ping_challenge, parse_qos_ping_request, AppProof, HealthResponse, HealthStatus,
    QosPingResponse, ServiceInfo,
};

use crate::http::{self, PublicError};
use crate::request::sign_ephemeral_low_s;

/// The keys and digests QOS hands an application.
pub struct QosState {
    pub ephemeral: P256Pair,
    pub quorum: P256Pair,
    pub manifest_digest: [u8; 32],
    pub executable_digest: [u8; 32],
}

/// Loads QOS-owned state from the canonical paths and checks the Quorum key
/// against the approved manifest. Failures are deliberately free of key material.
pub fn load_qos_state() -> io::Result<QosState> {
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
    Ok(QosState {
        ephemeral,
        quorum,
        manifest_digest,
        executable_digest,
    })
}

/// A running release: what it advertises and the QOS keys it answers with.
#[derive(Clone)]
pub struct Service {
    pub info: Arc<ServiceInfo>,
    pub ephemeral: Arc<P256Pair>,
    pub quorum: Arc<P256Pair>,
}

#[derive(Clone)]
struct Routes<H> {
    service: Service,
    operations: H,
}

/// `operations` answers `POST /v1/operations`.
pub fn router<H, F>(service: Service, operations: H) -> Router
where
    H: Fn(Bytes) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    Router::new().fallback(dispatch::<H, F>).with_state(Routes {
        service,
        operations,
    })
}

/// `/v1/ping` and `/v1/operations` take JSON posts. `/health` is process
/// readiness only and MUST NOT include release, key, or deployment
/// identifiers; `/v1/info` is discovery data, not a trust root.
async fn dispatch<H, F>(State(routes): State<Routes<H>>, request: Request<Body>) -> Response<Body>
where
    H: Fn(Bytes) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    let service = &routes.service;
    let (parts, body) = request.into_parts();
    let body_limit = usize::try_from(
        service
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
        ("POST", "/v1/ping") => handle_ping(service, &body),
        ("POST", "/v1/operations") => (routes.operations)(body).await,
        ("GET", "/health") => match jcs_serialize(&HealthResponse {
            status: HealthStatus::Healthy,
        }) {
            Ok(body) => http::ok(body),
            Err(_) => PublicError::Unavailable.into_response(),
        },
        ("GET", "/v1/info") => match jcs_serialize(&*service.info) {
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

fn handle_ping(service: &Service, body: &[u8]) -> Response<Body> {
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
    let Ok(plaintext) = service.quorum.decrypt(&request.encrypted_challenge) else {
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

    let Ok(signature) = sign_ephemeral_low_s(&service.ephemeral, proof_payload.as_bytes()) else {
        return PublicError::Unavailable.into_response();
    };
    let response = QosPingResponse {
        version: API_VERSION,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: service.ephemeral.public_key().to_bytes(),
            proof_payload: proof_payload.to_owned(),
            signature,
        },
    };
    match jcs_serialize(&response) {
        Ok(body) => http::ok(body),
        Err(_) => PublicError::Unavailable.into_response(),
    }
}

/// Serves `router` at `address` until SIGINT or SIGTERM, the signals QOS and a shell send.
pub async fn serve(address: SocketAddr, router: Router) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use zolana_tvc_protocol::constants::{QOS_P256_PUBLIC_LEN, RAW_P256_SIGNATURE_LEN};
    use zolana_tvc_protocol::crypto::{verify_p256_message, QosP256Public};
    use zolana_tvc_protocol::encoding::parse_strict_json;
    use zolana_tvc_protocol::types::{OperationKind, QosPingChallenge, QosPingRequest};

    use super::*;
    use crate::{App, Release, NETWORK};

    fn info(quorum: &P256Pair, ephemeral: &P256Pair) -> ServiceInfo {
        let app = App {
            operations: &[OperationKind::Decrypt],
            proof_type: "spr.tvc.test.v1",
        };
        Release {
            security_domain_id: [0x11; 32],
            release_id: "tvc-pet-test".to_owned(),
            quorum_key_id: "quorum-test".to_owned(),
            quorum_key_epoch: 1,
        }
        .service_info(&app, [0x22; 32], [0x33; 32], quorum, ephemeral)
    }

    /// Refuses every operation, as an application refuses a malformed one.
    fn app(quorum: P256Pair, ephemeral: P256Pair) -> Router {
        let service = Service {
            info: Arc::new(info(&quorum, &ephemeral)),
            ephemeral: Arc::new(ephemeral),
            quorum: Arc::new(quorum),
        };
        router(service, |_| async {
            PublicError::InvalidRequest.into_response()
        })
    }

    async fn response_body(response: Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn health_is_exact() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let response = app(quorum, ephemeral)
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
        let ephemeral_public_key = ephemeral.public_key().to_bytes();
        let expected = info(&quorum, &ephemeral);
        let response = app(quorum, ephemeral)
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let actual: ServiceInfo = parse_strict_json(&response_body(response).await).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.network, NETWORK);
        assert_eq!(actual.ephemeral_public_key, ephemeral_public_key);
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
        let response = app(quorum, ephemeral)
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
        let app = app(quorum, ephemeral);

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
        let app = app(quorum, ephemeral);

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
        let app = app(quorum, ephemeral);
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
}
