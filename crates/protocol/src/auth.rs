//! Direct P-256/SHA-256 client authorization. No generic signer API.

use sha2::{Digest, Sha256};

use crate::constants::CLIENT_KEY_ID_PREFIX;
use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::{client_auth_digest, request_digest};
use crate::error::{ErrorCode, TvcError};
use crate::types::{ClientAuthorizationScheme, OperationRequest};

/// The ID a request names its client key by, as descriptors and grants do.
pub fn client_key_id(client_public_key: &[u8]) -> String {
    let digest = Sha256::digest(client_public_key);
    format!("{CLIENT_KEY_ID_PREFIX}{}", hex::encode(&digest[..16]))
}

pub fn authorize_operation_request(
    mut request: OperationRequest,
    client_secret: &[u8; 32],
) -> Result<OperationRequest, TvcError> {
    if request.authorization.scheme != ClientAuthorizationScheme::P256Sha256 {
        return Err(TvcError::new(ErrorCode::UnauthorizedClient));
    }
    let digest = client_auth_digest(&request_digest(&request)?);
    request.authorization.signature = sign_p256_prehash(client_secret, &digest)?.to_vec();
    Ok(request)
}

pub fn verify_client_authorization(
    request: &OperationRequest,
    client_public_sec1: &[u8],
) -> Result<(), TvcError> {
    if request.authorization.scheme != ClientAuthorizationScheme::P256Sha256 {
        return Err(TvcError::new(ErrorCode::UnauthorizedClient));
    }
    if request.authorization.client_key_id.is_empty() {
        return Err(TvcError::new(ErrorCode::UnauthorizedClient));
    }
    let digest = client_auth_digest(&request_digest(request)?);
    verify_p256_prehash(
        client_public_sec1,
        &digest,
        &request.authorization.signature,
    )
    .map_err(|_| TvcError::new(ErrorCode::UnauthorizedClient))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_key_id_is_the_prefix_and_a_truncated_digest() {
        assert_eq!(
            client_key_id(&[4; 65]),
            "tvc-browser-p256-9bda95bda1ef8f1b61f6d47223f4a119"
        );
    }
}
