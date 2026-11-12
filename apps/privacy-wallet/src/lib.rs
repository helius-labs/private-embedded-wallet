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

use axum::Router;
use qos_p256::P256Pair;
use spr_tvc_enclave::{App, Service};
use zolana_tvc_protocol::constants::TVC_APP_PROOF_TYPE;
use zolana_tvc_protocol::types::ServiceInfo;

mod custody;
mod network;
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

pub use network::{Net, NET};
pub use operations::OPERATIONS;
pub use spr_tvc_enclave::Release as DiscoveryConfig;

pub(crate) const APP: App = App {
    operations: &OPERATIONS,
    proof_type: TVC_APP_PROOF_TYPE,
};

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
                provisioning_public: NET.provisioning,
                grant_public: NET.grant,
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
    let qos = spr_tvc_enclave::load_qos_state()?;
    let info = config.service_info(
        &APP,
        qos.manifest_digest,
        qos.executable_digest,
        &qos.quorum,
        &qos.ephemeral,
    );
    Ok(AppState::ready(info, qos.ephemeral, qos.quorum))
}

pub fn router(state: AppState) -> Router {
    let service = Service {
        info: Arc::clone(&state.info),
        ephemeral: Arc::clone(&state.runtime.ephemeral),
        quorum: Arc::clone(&state.runtime.quorum),
    };
    spr_tvc_enclave::router(service, move |body| {
        let state = state.clone();
        async move { operations::handle(&state, &body).await }
    })
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use zolana_tvc_protocol::encoding::parse_strict_json;

    use super::*;

    fn app() -> Router {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let config = DiscoveryConfig {
            security_domain_id: [0x11; 32],
            release_id: "tvc-pet-test".to_owned(),
            quorum_key_id: "quorum-test".to_owned(),
            quorum_key_epoch: 1,
        };
        let info = config.service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
        router(AppState::ready(info, ephemeral, quorum))
    }

    async fn body(response: axum::http::Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn info_advertises_the_image_network_and_the_wallet_operations() {
        let response = app()
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let info: ServiceInfo = parse_strict_json(&body(response).await).unwrap();
        assert_eq!(info.network, NET.network);
        assert_eq!(info.supported_operations, OPERATIONS);
        assert_eq!(info.proof_type, TVC_APP_PROOF_TYPE);
    }

    #[tokio::test]
    async fn operations_reach_the_wallet_handler() {
        let response = app()
            .oneshot(
                Request::post("/v1/operations")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body(response).await, r#"{"error":"InvalidRequest"}"#);
    }
}
