//! Which addresses have service keys, and what their owner must show.

use std::str::FromStr;

use ed25519_dalek::{Signature, VerifyingKey};
use solana_pubkey::Pubkey;
use spr_tvc_enclave::Failure;
use zolana_tvc_protocol::decryption_service::{decrypt_message, ADDRESS_LEN};
use zolana_tvc_protocol::types::Network;

/// The key of an address a key can sign for: on the curve, not of small order.
pub(crate) fn address_key(address: &str) -> Result<VerifyingKey, Failure> {
    Pubkey::from_str(address)
        .ok()
        .and_then(|address| VerifyingKey::from_bytes(&address.to_bytes()).ok())
        .filter(|key| !key.is_weak())
        .ok_or(Failure::Invalid)
}

/// The signer's address, once it signed the request with this digest. Strict Ed25519.
pub(crate) fn authorized(
    signer_address: &str,
    signature: &[u8; 64],
    network: Network,
    request_digest: &[u8; 32],
) -> Result<[u8; ADDRESS_LEN], Failure> {
    let key = address_key(signer_address)?;
    let address = key.to_bytes();
    key.verify_strict(
        &decrypt_message(&address, network, request_digest),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| Failure::Invalid)?;
    Ok(address)
}
