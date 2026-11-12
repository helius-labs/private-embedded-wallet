//! Decryption-service TVC application; see `crates/protocol/README.md#decryption-service`.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;

use axum::Router;
use spr_tvc_enclave::{App, Release, Service};
use zolana_tvc_protocol::decryption_service::SERVICE_PROOF_TYPE;

mod backup;
mod custody;
mod keys;
mod operations;
mod owner;
mod seed;

pub use custody::Custody;

const APP: App = App {
    operations: &operations::OPERATIONS,
    proof_type: SERVICE_PROOF_TYPE,
};

#[derive(Clone)]
pub struct State {
    service: Service,
    custody: Arc<Custody>,
}

/// Loads the QOS keys and binds discovery to the approved manifest.
pub fn load_qos_state(release: Release, custody: Custody) -> io::Result<State> {
    custody.check()?;
    Ok(State {
        service: Service::load(release, &APP)?,
        custody: Arc::new(custody),
    })
}

pub fn router(state: State) -> Router {
    spr_tvc_enclave::router(state.service.clone(), move |body| {
        let state = state.clone();
        async move { operations::handle(&state, &body) }
    })
}
