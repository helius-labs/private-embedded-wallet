//! Request bindings against the running release, as `/v1/info` describes it.

use spr_tvc_protocol::constants::API_VERSION;
use spr_tvc_protocol::error::{ErrorCode, TvcError};
use spr_tvc_protocol::types::{OperationRequest, ServiceInfo};

pub(super) fn check_request_bindings(
    request: &OperationRequest,
    running: &ServiceInfo,
) -> Result<(), TvcError> {
    if request.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if request.wallet_descriptor.network != running.network {
        return Err(TvcError::new(ErrorCode::NetworkMismatch));
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
