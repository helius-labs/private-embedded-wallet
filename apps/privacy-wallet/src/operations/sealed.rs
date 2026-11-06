//! The sealed derivation seed and the privacy roles expanded from it.

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey;
use spr_keypair::shielded::ShieldedAddress;
use spr_keypair::{derivation, Curve, NullifierKey, PublicKey, ViewingKey};
use zeroize::{Zeroize, Zeroizing};
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::digest::{descriptor_digest, sealed_seed_digest, wallet_id_hash};
use zolana_tvc_protocol::types::{OperationRequest, SealedSeed};

use super::{Failure, DERIVATION_SUITE};
use crate::Runtime;

/// The wallet's privacy roles for one request. The seed they expand from is
/// dropped as soon as they exist.
pub(crate) struct Roles {
    pub owner: PublicKey,
    pub nullifier_key: NullifierKey,
    pub viewing_key: ViewingKey,
}

impl Roles {
    /// `seed` must be the wallet key's signature over its derivation message;
    /// anything else is not this wallet's identity.
    pub(crate) fn from_seed(
        ed25519_public_key: &[u8; 32],
        seed: &[u8; 64],
    ) -> Result<Self, Failure> {
        let owner = PublicKey::from_ed25519(ed25519_public_key);
        let message = derivation::ed25519_derivation_message(ed25519_public_key);
        if !owner.verify_message(&message, seed) {
            return Err(Failure::Invalid);
        }
        let (nullifier_key, viewing_key) =
            derivation::expand_roles(seed, Curve::Ed25519).map_err(|_| Failure::Invalid)?;
        Ok(Self {
            owner,
            nullifier_key,
            viewing_key,
        })
    }

    pub(crate) fn address(&self) -> Result<ShieldedAddress, Failure> {
        Ok(ShieldedAddress {
            signing_pubkey: self.owner,
            nullifier_pubkey: self
                .nullifier_key
                .pubkey()
                .map_err(|_| Failure::Unavailable)?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }
}

/// Borsh contents of the sealed seed. The seed is the only secret; every other
/// field pins the blob to one descriptor and Quorum key epoch. The descriptor
/// digest covers the Turnkey wallet and its address, so it pins the wallet too.
#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct UnsealedSeed {
    pub version: u8,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub descriptor_digest: [u8; 32],
    pub derivation_suite: String,
    pub derivation_seed: [u8; 64],
}

impl Drop for UnsealedSeed {
    fn drop(&mut self) {
        self.derivation_seed.zeroize();
    }
}

/// Seals `seed` for the wallet a request names. Returns the wire bytes and
/// their digest.
pub(super) fn seal(
    request: &OperationRequest,
    runtime: &Runtime,
    seed: &[u8; 64],
) -> Result<(Vec<u8>, [u8; 32]), Failure> {
    let contents = UnsealedSeed {
        version: API_VERSION,
        quorum_key_id: request.quorum_key_id.clone(),
        quorum_key_epoch: request.quorum_key_epoch,
        descriptor_digest: descriptor_digest(&request.wallet_descriptor)
            .map_err(|_| Failure::Invalid)?,
        derivation_suite: DERIVATION_SUITE.to_owned(),
        derivation_seed: *seed,
    };
    let plaintext = Zeroizing::new(borsh::to_vec(&contents).map_err(|_| Failure::Unavailable)?);
    let sealed = SealedSeed {
        version: API_VERSION,
        quorum_key_id: contents.quorum_key_id.clone(),
        quorum_key_epoch: contents.quorum_key_epoch,
        wallet_id_hash: wallet_id_hash(&request.wallet_descriptor.wallet_id()),
        ciphertext: runtime
            .quorum
            .public_key()
            .encrypt(&plaintext)
            .map_err(|_| Failure::Unavailable)?,
    };
    let bytes = borsh::to_vec(&sealed).map_err(|_| Failure::Unavailable)?;
    let digest = sealed_seed_digest(&bytes);
    Ok((bytes, digest))
}

/// Unseals the request's seed into the wallet's roles. The envelope is
/// checked against the request and the contents against both the envelope and
/// the descriptor, so a blob works only under the descriptor and Quorum key
/// epoch it was issued for. Returns the roles and the sealed-seed digest.
pub(super) fn unseal(
    request: &OperationRequest,
    runtime: &Runtime,
) -> Result<(Roles, [u8; 32]), Failure> {
    let bytes = request.sealed_seed.as_deref().ok_or(Failure::Invalid)?;
    let sealed = SealedSeed::try_from_slice(bytes).map_err(|_| Failure::Invalid)?;
    let descriptor = &request.wallet_descriptor;
    if sealed.version != API_VERSION
        || sealed.quorum_key_id != request.quorum_key_id
        || sealed.quorum_key_epoch != request.quorum_key_epoch
        || sealed.wallet_id_hash != wallet_id_hash(&descriptor.wallet_id())
    {
        return Err(Failure::Invalid);
    }
    let plaintext = Zeroizing::new(
        runtime
            .quorum
            .decrypt(&sealed.ciphertext)
            .map_err(|_| Failure::Invalid)?,
    );
    let contents = UnsealedSeed::try_from_slice(&plaintext).map_err(|_| Failure::Invalid)?;
    let owner = Pubkey::from_str(&descriptor.address).map_err(|_| Failure::Invalid)?;
    if contents.version != API_VERSION
        || contents.quorum_key_id != sealed.quorum_key_id
        || contents.quorum_key_epoch != sealed.quorum_key_epoch
        || contents.descriptor_digest
            != descriptor_digest(descriptor).map_err(|_| Failure::Invalid)?
        || contents.derivation_suite != DERIVATION_SUITE
    {
        return Err(Failure::Invalid);
    }
    let roles = Roles::from_seed(&owner.to_bytes(), &contents.derivation_seed)?;
    Ok((roles, sealed_seed_digest(bytes)))
}
