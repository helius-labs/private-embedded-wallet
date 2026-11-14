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
use spr_tvc_enclave::{App, Release, Service};
use spr_tvc_protocol::constants::TVC_APP_PROOF_TYPE;
use spr_tvc_protocol::types::ServiceInfo;

mod custody;
mod network;
mod operations;
mod turnkey;

#[cfg(feature = "local-dev")]
mod local_dev;
#[cfg(feature = "local-dev")]
mod local_prover;
#[cfg(feature = "local-dev")]
pub use local_dev::{local_unattested_state, LocalProverTrust};
#[cfg(feature = "local-dev")]
pub use local_prover::{LocalProver, POLICY_PATH};

pub use network::{Net, NET};
pub use operations::OPERATIONS;

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
    pub fn ready(service: Service) -> Self {
        Self {
            info: service.info,
            runtime: Arc::new(Runtime {
                ephemeral: service.ephemeral,
                custody: Arc::new(custody::TurnkeyCustody::new(Arc::clone(&service.quorum))),
                quorum: service.quorum,
                provisioning_public: NET.provisioning,
                grant_public: NET.grant,
                prover: operations::ProverTrust::image(),
            }),
        }
    }
}

/// Loads the QOS keys and binds discovery to the approved manifest.
pub fn load_qos_state(release: Release) -> io::Result<AppState> {
    Service::load(release, &APP).map(AppState::ready)
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
    use spr_tvc_enclave::testing::{self, body};
    use tower::ServiceExt as _;
    use spr_tvc_protocol::encoding::parse_strict_json;

    use super::*;

    fn app() -> Router {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let info =
            testing::release().service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
        router(AppState::ready(Service::new(info, ephemeral, quorum)))
    }

    #[tokio::test]
    async fn info_advertises_the_image_network_and_the_wallet_operations() {
        let response = app()
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let info: ServiceInfo = parse_strict_json(&body(response).await).unwrap();
        assert_eq!(info.network, spr_tvc_enclave::NETWORK);
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
