//! Splitting the master seed among backup holders, and rebuilding it from their shares.

use qos_crypto::shamir::{shares_generate, shares_reconstruct};
use spr_tvc_enclave::{Failure, Service};
use zeroize::Zeroizing;
use zolana_tvc_protocol::crypto::qos_encrypt;
use zolana_tvc_protocol::decryption_service::{
    backup_set_id, BackupShare, HolderShare, ServiceResult,
};
use zolana_tvc_protocol::encoding::{jcs_serialize, parse_strict_json};

use crate::custody::Custody;
use crate::keys::MASTER_SEED_LEN;

const SHARE_VERSION: u8 = 1;

/// One share per holder, each encrypted to that holder.
pub(crate) fn split(
    seed: &[u8; MASTER_SEED_LEN],
    custody: &Custody,
) -> Result<ServiceResult, Failure> {
    let threshold = custody.backup_threshold.ok_or(Failure::Invalid)?;
    let holders = &custody.backup_holders;
    let set_id = backup_set_id(threshold, holders);
    let parts =
        shares_generate(seed, holders.len(), threshold.into()).map_err(|_| Failure::Unavailable)?;
    let shares = holders
        .iter()
        .zip(parts)
        .map(|(holder, part)| {
            let share = BackupShare {
                version: SHARE_VERSION,
                set_id,
                threshold,
                share: part.to_vec(),
            };
            let plaintext =
                Zeroizing::new(jcs_serialize(&share).map_err(|_| Failure::Unavailable)?);
            Ok(HolderShare {
                holder_public_key: holder.clone(),
                ciphertext: qos_encrypt(holder, plaintext.as_bytes())
                    .map_err(|_| Failure::Unavailable)?,
            })
        })
        .collect::<Result<_, Failure>>()?;
    Ok(ServiceResult::Backup {
        set_id,
        threshold,
        shares,
    })
}

/// The seed rebuilt from shares of one set; the caller checks it against the pinned commitment.
pub(crate) fn rebuild(
    envelopes: &[Vec<u8>],
    service: &Service,
) -> Result<Zeroizing<[u8; MASTER_SEED_LEN]>, Failure> {
    let shares = envelopes
        .iter()
        .map(|envelope| {
            let plaintext = Zeroizing::new(
                service
                    .quorum
                    .decrypt(envelope)
                    .map_err(|_| Failure::Invalid)?,
            );
            let plaintext = std::str::from_utf8(&plaintext).map_err(|_| Failure::Invalid)?;
            parse_strict_json::<BackupShare>(plaintext).map_err(|_| Failure::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first = shares.first().ok_or(Failure::Invalid)?;
    if first.version != SHARE_VERSION
        || shares.len() < usize::from(first.threshold)
        || shares
            .iter()
            .any(|share| share.set_id != first.set_id || share.threshold != first.threshold)
    {
        return Err(Failure::Invalid);
    }
    let parts: Vec<Zeroizing<Vec<u8>>> = shares
        .iter()
        .map(|share| Zeroizing::new(share.share.clone()))
        .collect();
    let secret = shares_reconstruct(&parts).map_err(|_| Failure::Invalid)?;
    let seed: [u8; MASTER_SEED_LEN] = secret.as_slice().try_into().map_err(|_| Failure::Invalid)?;
    Ok(Zeroizing::new(seed))
}
