//! What every TVC application here serves around its own operations.

#![forbid(unsafe_code)]

mod cipher;
pub mod http;
#[cfg(feature = "local-dev")]
pub mod local;
mod release;
mod request;
mod service;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use cipher::{check_batch, open_ciphertexts};
pub use release::{App, Release, NETWORK};
pub use request::{open_envelope, respond, Failure, ProofBinding};
pub use service::{router, serve, Service};
