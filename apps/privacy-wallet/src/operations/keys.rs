//! The wallet's privacy roles as batched functions: opening ciphertexts with
//! the viewing key, deriving nullifiers and merge values from the nullifier
//! secret, and minting per-transaction viewing keys. No answer is a long-lived
//! secret, and no answer is interpreted here: the client decodes plaintexts
//! and matches derived values against what the chain published.

use spr_keypair::viewing_key::Salt;
use spr_keypair::{ViewingKey, X25519Pubkey};
use spr_transaction::instructions::merge::{
    merge_dummy_nullifier, merge_output_blinding, merge_output_key, merge_private_tx_blinding,
};
use zolana_tvc_protocol::constants::MAX_ITEMS_PER_BATCH;
use zolana_tvc_protocol::types::{
    DecryptItem, DecryptLabel, DeriveItem, OperationResult, TransactionKeyItem,
};

use super::sealed::Roles;
use super::Failure;

fn check_batch<T>(items: &[T]) -> Result<(), Failure> {
    if items.is_empty() || items.len() as u64 > MAX_ITEMS_PER_BATCH {
        return Err(Failure::Invalid);
    }
    Ok(())
}

/// The viewing key `public_key` names. This wallet holds one, so a request
/// under any other key is not a request about this wallet.
fn viewing_key<'a>(roles: &'a Roles, public_key: &[u8]) -> Result<&'a ViewingKey, Failure> {
    if roles.viewing_key.pubkey().as_bytes() != public_key {
        return Err(Failure::Invalid);
    }
    Ok(&roles.viewing_key)
}

/// A tagged X25519 public key, `0x04 || u` with a canonical `u`.
fn x25519(bytes: &[u8]) -> Result<X25519Pubkey, Failure> {
    let key: [u8; 33] = bytes.try_into().map_err(|_| Failure::Invalid)?;
    X25519Pubkey::from_bytes(key).map_err(|_| Failure::Invalid)
}

/// Applies the transfer cipher to each ciphertext. The cipher is
/// unauthenticated and never fails on content, so every item answers; a
/// ciphertext that was not for this wallet answers with bytes that do not
/// decode, which the client detects against the indexed commitment.
pub(super) fn decrypt(roles: &Roles, items: &[DecryptItem]) -> Result<OperationResult, Failure> {
    check_batch(items)?;
    let plaintexts = items
        .iter()
        .map(|item| {
            let viewing = viewing_key(roles, &item.viewing_public_key)?;
            let transaction_key = x25519(&item.transaction_viewing_public_key)?;
            let salt: Salt = item
                .salt
                .as_slice()
                .try_into()
                .map_err(|_| Failure::Invalid)?;
            match item.label {
                DecryptLabel::Transfer => {
                    let slot = u32::try_from(item.slot_index).map_err(|_| Failure::Invalid)?;
                    viewing.decrypt_utxo(&item.ciphertext, &transaction_key, salt, slot)
                }
                DecryptLabel::RingDeposit => {
                    if item.slot_index != 0 {
                        return Err(Failure::Invalid);
                    }
                    viewing.decrypt_ring_deposit(&item.ciphertext, &transaction_key, salt)
                }
            }
            .map_err(|_| Failure::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationResult::Decrypt { plaintexts })
}

pub(super) fn derive(roles: &Roles, items: &[DeriveItem]) -> Result<OperationResult, Failure> {
    check_batch(items)?;
    let values = items
        .iter()
        .map(|item| match item {
            DeriveItem::Nullifier {
                utxo_hash,
                blinding,
            } => roles
                .nullifier_key
                .nullifier(utxo_hash, blinding)
                .map_err(|_| Failure::Invalid),
            DeriveItem::MergeDummyNullifier {
                first_nullifier,
                slot_index,
            } => {
                let slot = u8::try_from(*slot_index).map_err(|_| Failure::Invalid)?;
                merge_dummy_nullifier(&roles.nullifier_key, first_nullifier, slot)
                    .map_err(|_| Failure::Invalid)
            }
            DeriveItem::MergeOutputBlinding { first_nullifier } => {
                merge_output_blinding(&roles.nullifier_key, first_nullifier)
                    .map_err(|_| Failure::Invalid)
            }
            DeriveItem::MergePrivateTxBlinding { first_nullifier } => {
                merge_private_tx_blinding(&roles.nullifier_key, first_nullifier)
                    .map_err(|_| Failure::Invalid)
            }
            DeriveItem::MergeOutputKey { first_nullifier } => {
                merge_output_key(&roles.nullifier_key, first_nullifier)
                    .map_err(|_| Failure::Invalid)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationResult::Derive { values })
}

/// Per-transaction viewing secrets. The derivation from the viewing key is
/// one way, so a secret returned here opens one transaction and says nothing
/// about the viewing key or any other transaction.
pub(super) fn transaction_keys(
    roles: &Roles,
    items: &[TransactionKeyItem],
) -> Result<OperationResult, Failure> {
    check_batch(items)?;
    let secrets = items
        .iter()
        .map(|item| {
            let viewing = viewing_key(roles, &item.viewing_public_key)?;
            viewing
                .get_transaction_viewing_key(&item.first_nullifier)
                .map(|key| *key.secret_bytes())
                .map_err(|_| Failure::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationResult::TransactionKeys { secrets })
}
