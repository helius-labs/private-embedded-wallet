//! Opening pool ciphertexts with a viewing key held in the enclave.

use spr_keypair::viewing_key::Salt;
use spr_keypair::{ViewingKey, X25519Pubkey};
use spr_tvc_protocol::constants::MAX_ITEMS_PER_BATCH;
use spr_tvc_protocol::types::{DecryptItem, DecryptLabel};

use crate::Failure;

/// A batch holds between one and `MAX_ITEMS_PER_BATCH` items.
pub fn check_batch<T>(items: &[T]) -> Result<(), Failure> {
    if items.is_empty() || items.len() as u64 > MAX_ITEMS_PER_BATCH {
        return Err(Failure::Invalid);
    }
    Ok(())
}

/// The pool cipher's output for each item under `viewing`; for another key's item, noise.
pub fn open_ciphertexts(
    viewing: &ViewingKey,
    items: &[DecryptItem],
) -> Result<Vec<Vec<u8>>, Failure> {
    check_batch(items)?;
    items
        .iter()
        .map(|item| {
            if viewing.pubkey().as_bytes() != item.viewing_public_key.as_slice() {
                return Err(Failure::Invalid);
            }
            let transaction_key: [u8; 33] = item
                .transaction_viewing_public_key
                .as_slice()
                .try_into()
                .map_err(|_| Failure::Invalid)?;
            let transaction_key =
                X25519Pubkey::from_bytes(transaction_key).map_err(|_| Failure::Invalid)?;
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
        .collect()
}
