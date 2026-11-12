//! What an owner must show, and how an answer is sealed to the owner's wallet.

use std::str::FromStr;

use ed25519_dalek::{Signature, VerifyingKey};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeS, Serializable};
use rand_core::{OsRng, UnwrapErr};
use solana_pubkey::Pubkey;
use spr_keypair::X25519Pubkey;
use zolana_tvc_protocol::decryption_service::{OwnerAuthorization, ServiceResult, ADDRESS_LEN};

use crate::operations::Failure;

/// The key of an address a key can sign for: on the curve, not of small order.
pub(super) fn signer(address: &str) -> Result<VerifyingKey, Failure> {
    Pubkey::from_str(address)
        .ok()
        .and_then(|address| VerifyingKey::from_bytes(&address.to_bytes()).ok())
        .filter(|key| !key.is_weak())
        .ok_or(Failure::Invalid)
}

/// The signer's address, once it signed the message built for it. Strict Ed25519.
pub(super) fn authorized(
    authorization: &OwnerAuthorization,
    message: impl FnOnce(&[u8; ADDRESS_LEN]) -> Vec<u8>,
) -> Result<[u8; ADDRESS_LEN], Failure> {
    let key = signer(&authorization.signer)?;
    let address = key.to_bytes();
    key.verify_strict(
        &message(&address),
        &Signature::from_bytes(&authorization.signature),
    )
    .map_err(|_| Failure::Invalid)?;
    Ok(address)
}

/// HPKE base mode to the wallet viewing key; a non-canonical or low-order key fails.
pub(super) fn seal(
    authorization: &OwnerAuthorization,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<ServiceResult, Failure> {
    let recipient = X25519Pubkey::from_bytes(authorization.wallet_viewing_public_key)
        .ok()
        .and_then(|key| <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&key.u()).ok())
        .ok_or(Failure::Invalid)?;
    let (enc, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &recipient,
        info,
        plaintext,
        aad,
        &mut UnwrapErr(OsRng),
    )
    .map_err(|_| Failure::Invalid)?;
    Ok(ServiceResult::Sealed {
        enc: enc.to_bytes().into(),
        ciphertext,
    })
}
