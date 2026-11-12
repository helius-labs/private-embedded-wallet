//! Decryption-service TVC application.
//!
//! Lets a Solana address receive private transfers before its owner registers
//! a wallet. The enclave derives one viewing key and one nullifier key per
//! address, its service keys, from a master seed sealed to the Quorum key. A
//! sender gets the public keys. The owner later signs with the address, and
//! the enclave opens a batch of outputs for the owner's wallet.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;

use axum::Router;
use spr_tvc_enclave::{App, Release, Service};
use zolana_tvc_protocol::decryption_service::SERVICE_PROOF_TYPE;

mod keys;
mod operations;
mod owner;
mod seed;

pub use operations::OPERATIONS;

const APP: App = App {
    operations: &OPERATIONS,
    proof_type: SERVICE_PROOF_TYPE,
};

/// Loads QOS-owned state and binds discovery to the approved manifest.
pub fn load_qos_state(release: Release) -> io::Result<Service> {
    let qos = spr_tvc_enclave::load_qos_state()?;
    let info = release.service_info(
        &APP,
        qos.manifest_digest,
        qos.executable_digest,
        &qos.quorum,
        &qos.ephemeral,
    );
    Ok(Service {
        info: Arc::new(info),
        ephemeral: Arc::new(qos.ephemeral),
        quorum: Arc::new(qos.quorum),
    })
}

pub fn router(service: Service) -> Router {
    spr_tvc_enclave::router(service.clone(), move |body| {
        let service = service.clone();
        async move { operations::handle(&service, &body) }
    })
}
