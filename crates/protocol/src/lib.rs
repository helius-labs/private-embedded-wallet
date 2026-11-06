//! Wire types, canonical encoding, digests, and P-256/QOS primitives shared by
//! the TVC application and its clients.
//!
//! This crate does not verify AWS Nitro Boot Proofs or bind Turnkey policy
//! evidence to an activity.

#![forbid(unsafe_code)]

pub mod auth;
pub mod constants;
pub mod crypto;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod grant;
pub mod release;
pub mod types;

pub use auth::{authorize_operation_request, client_key_id, verify_client_authorization};
pub use error::{ErrorCode, TvcError};
pub use grant::{sign_wallet_grant, verify_wallet_grant};
pub use release::{
    policy_signing_digest, sign_release_policy, verify_signed_release_policy,
    PinnedReleaseAuthorities, ReleaseAuthorityKey,
};
pub use types::{
    AppProof, ClientAuthorization, ClientGrant, DecryptItem, DecryptLabel, DeriveItem,
    EncryptedRequest, EncryptedResponse, FailureStage, HealthResponse, HealthStatus, Network,
    Operation, OperationKind, OperationProofPayload, OperationRequest, OperationResult,
    ProverSealing, QosPingChallenge, QosPingRequest, QosPingResponse, ReleaseAuthoritySignature,
    ReleasePolicy, SealedProverRequest, SealedSeed, ServiceInfo, SignedReleasePolicy,
    TransactionKeyItem, WalletDescriptor, WalletGrant,
};
