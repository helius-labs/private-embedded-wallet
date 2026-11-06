//! Domain-separated SHA-256 digest constructors.

use sha2::{Digest, Sha256};

use crate::constants::{
    CLIENT_AUTH_DOMAIN, PROVISIONING_AUTH_DOMAIN, RELEASE_POLICY_DOMAIN, REQUEST_DIGEST_DOMAIN,
    REQUEST_ID_HASH_DOMAIN, RESULT_DIGEST_DOMAIN, SEALED_SEED_DIGEST_DOMAIN, WALLET_BINDING_DOMAIN,
    WALLET_GRANT_DOMAIN, WALLET_ID_HASH_DOMAIN,
};
use crate::encoding::{self, canonicalize_json_value, encode_lower_hex};
use crate::error::{ErrorCode, TvcError};
use crate::types::{OperationRequest, WalletDescriptor};

pub fn domain_separated_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `request_digest` omits only `authorization.signature`; `client_key_id` stays.
pub fn request_digest(request: &OperationRequest) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(request)?;
    let authorization = value
        .get_mut("authorization")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    if authorization.remove("signature").is_none() {
        return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
    }
    if !authorization.contains_key("client_key_id") {
        return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
    }
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        REQUEST_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// The text a client key signs for a request:
/// `spr-tvc-client-auth-v1:<request digest in lowercase hex>`.
pub fn client_auth_message(request_digest_bytes: &[u8; 32]) -> String {
    format!(
        "{CLIENT_AUTH_DOMAIN}:{}",
        encode_lower_hex(request_digest_bytes)
    )
}

/// SHA-256 of the UTF-8 [`client_auth_message`]: the digest ECDSA signs.
pub fn client_auth_digest(request_digest_bytes: &[u8; 32]) -> [u8; 32] {
    sha256(client_auth_message(request_digest_bytes).as_bytes())
}

/// The provisioner signs the descriptor without its own signature field.
pub fn descriptor_digest(descriptor: &WalletDescriptor) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(descriptor)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    object.remove("provisioning_signature");
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        PROVISIONING_AUTH_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// Names the wallet a descriptor is for, and nothing about its clients: the
/// network, security domain, Turnkey organization and wallet, and address. A
/// sealed seed carries it, so any descriptor of the wallet opens the seed,
/// whichever client key it lists.
pub fn wallet_binding_digest(descriptor: &WalletDescriptor) -> Result<[u8; 32], TvcError> {
    let wallet = serde_json::json!({
        "network": descriptor.network,
        "security_domain_id": encode_lower_hex(&descriptor.security_domain_id),
        "turnkey_organization_id": descriptor.turnkey_organization_id,
        "turnkey_wallet_id": descriptor.turnkey_wallet_id,
        "address": descriptor.address,
    });
    let canonical = canonicalize_json_value(&wallet)?;
    Ok(domain_separated_hash(
        WALLET_BINDING_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// The grant key signs the grant without its own signature field.
pub fn wallet_grant_digest(grant: &crate::types::WalletGrant) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(grant)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    object.remove("signature");
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        WALLET_GRANT_DOMAIN,
        canonical.as_bytes(),
    ))
}

pub fn result_digest(encrypted_result: &[u8]) -> [u8; 32] {
    domain_separated_hash(RESULT_DIGEST_DOMAIN, encrypted_result)
}

/// Digest of the exact sealed-seed wire bytes.
pub fn sealed_seed_digest(sealed_seed: &[u8]) -> [u8; 32] {
    domain_separated_hash(SEALED_SEED_DIGEST_DOMAIN, sealed_seed)
}

pub fn wallet_id_hash(wallet_id: &str) -> [u8; 32] {
    domain_separated_hash(WALLET_ID_HASH_DOMAIN, wallet_id.as_bytes())
}

pub fn request_id_hash(request_id: &[u8; 32]) -> [u8; 32] {
    domain_separated_hash(REQUEST_ID_HASH_DOMAIN, request_id)
}

pub fn release_policy_digest(policy_jcs: &[u8]) -> [u8; 32] {
    domain_separated_hash(RELEASE_POLICY_DOMAIN, policy_jcs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ClientGrant, Network, OperationKind};

    #[test]
    fn the_client_auth_message_is_the_domain_and_the_hex_request_digest() {
        let digest = [0xab; 32];
        let message = client_auth_message(&digest);
        assert_eq!(
            message,
            format!("spr-tvc-client-auth-v1:{}", "ab".repeat(32))
        );
        assert_eq!(client_auth_digest(&digest), sha256(message.as_bytes()));
    }

    fn descriptor() -> WalletDescriptor {
        WalletDescriptor {
            version: crate::constants::API_VERSION,
            security_domain_id: [0x11; 32],
            network: Network::Devnet,
            turnkey_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            turnkey_wallet_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            address: "4E2agEUkMiuP3ABYbYTYXuU7bYyqPb3uGsLqs7RDd1U5".to_owned(),
            allowed_clients: vec![ClientGrant {
                client_public_key: vec![0x04; 65],
                allowed_operations: vec![OperationKind::Decrypt],
            }],
            expires_at_ms: 1_800_086_400_000,
            provisioning_signature: vec![0; 64],
        }
    }

    #[test]
    fn the_descriptor_digest_covers_its_expiry() {
        let mut later = descriptor();
        later.expires_at_ms += 1;
        assert_ne!(
            descriptor_digest(&later).expect("digest"),
            descriptor_digest(&descriptor()).expect("digest")
        );
    }

    #[test]
    fn a_descriptor_is_current_until_the_clock_skew_past_its_expiry() {
        let descriptor = descriptor();
        let expires = descriptor.expires_at_ms;
        assert_eq!(descriptor.check_current(0), Ok(()));
        assert_eq!(
            descriptor.check_current(expires + crate::constants::MAX_CLOCK_SKEW_MS),
            Ok(())
        );
        assert_eq!(
            descriptor
                .check_current(expires + crate::constants::MAX_CLOCK_SKEW_MS + 1)
                .map_err(|error| error.code),
            Err(crate::error::ErrorCode::DescriptorExpired)
        );
    }

    #[test]
    fn the_wallet_binding_names_the_wallet_and_not_its_clients() {
        let digest = wallet_binding_digest(&descriptor()).expect("digest");

        let mut other_client = descriptor();
        other_client.allowed_clients[0].client_public_key = vec![0x05; 65];
        other_client.allowed_clients[0].allowed_operations = vec![OperationKind::Derive];
        other_client.expires_at_ms += 1;
        other_client.provisioning_signature = vec![1; 64];
        assert_eq!(
            wallet_binding_digest(&other_client).expect("digest"),
            digest
        );

        let others: [fn(&mut WalletDescriptor); 5] = [
            |d| d.network = Network::Mainnet,
            |d| d.security_domain_id = [0x12; 32],
            |d| d.turnkey_organization_id = "00000000-0000-4000-8000-000000000003".to_owned(),
            |d| d.turnkey_wallet_id = "00000000-0000-4000-8000-000000000004".to_owned(),
            |d| d.address = "11111111111111111111111111111111".to_owned(),
        ];
        for change in others {
            let mut other_wallet = descriptor();
            change(&mut other_wallet);
            assert_ne!(
                wallet_binding_digest(&other_wallet).expect("digest"),
                digest
            );
        }
    }
}
