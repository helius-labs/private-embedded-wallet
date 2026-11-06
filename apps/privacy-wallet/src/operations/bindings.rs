//! Request bindings against the running enclave / independently accepted release.

use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::error::{ErrorCode, TvcError};
use zolana_tvc_protocol::types::{
    reject_production_environment, EncryptedRequest, Environment, OperationRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningEnclave {
    pub release_id: String,
    pub manifest_digest: [u8; 32],
    pub executable_digest: [u8; 32],
    pub security_domain_id: [u8; 32],
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub environment: Environment,
}

pub fn check_encrypted_request_bindings(
    outer: &EncryptedRequest,
    running: &RunningEnclave,
) -> Result<(), TvcError> {
    if outer.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if outer.quorum_key_id != running.quorum_key_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if outer.quorum_key_epoch != running.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    Ok(())
}

pub fn check_request_bindings(
    request: &OperationRequest,
    running: &RunningEnclave,
) -> Result<(), TvcError> {
    if request.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    reject_production_environment(request.wallet_descriptor.environment)?;
    if request.wallet_descriptor.environment != running.environment {
        return Err(TvcError::new(ErrorCode::WalletBindingMismatch));
    }
    if request.target_release_id != running.release_id
        || request.target_manifest_digest != running.manifest_digest
        || request.target_executable_digest != running.executable_digest
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if request.wallet_descriptor.security_domain_id != running.security_domain_id {
        return Err(TvcError::new(ErrorCode::WalletBindingMismatch));
    }
    if request.wallet_descriptor.turnkey_wallet_id.is_empty() {
        return Err(TvcError::new(ErrorCode::InvalidWalletDescriptor));
    }
    if request.quorum_key_id != running.quorum_key_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if request.quorum_key_epoch != running.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    Ok(())
}
