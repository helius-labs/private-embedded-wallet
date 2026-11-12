//! Decryption-service TVC application; see `crates/protocol/README.md#decryption-service`.

#![forbid(unsafe_code)]

use std::io;

use axum::Router;
use spr_tvc_enclave::{App, Release, Service};
use zolana_tvc_protocol::decryption_service::SERVICE_PROOF_TYPE;

mod keys;
mod operations;
mod owner;

const APP: App = App {
    operations: &operations::OPERATIONS,
    proof_type: SERVICE_PROOF_TYPE,
};

/// Loads the QOS keys and binds discovery to the approved manifest.
pub fn load_qos_state(release: Release) -> io::Result<Service> {
    Service::load(release, &APP)
}

pub fn router(service: Service) -> Router {
    spr_tvc_enclave::router(service.clone(), move |body| {
        let service = service.clone();
        async move { operations::handle(&service, &body) }
    })
}
