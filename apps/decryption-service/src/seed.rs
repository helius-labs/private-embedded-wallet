//! The master seed, sealed to the Quorum key and presented with each request.

use borsh::{BorshDeserialize, BorshSerialize};
use qos_p256::P256Pair;
use rand_core::{OsRng, RngCore as _, UnwrapErr};
use spr_tvc_enclave::{Failure, Service};
use zeroize::{Zeroize, Zeroizing};
use zolana_tvc_protocol::decryption_service::MASTER_SEED_SIGNATURE_DOMAIN;
use zolana_tvc_protocol::digest::sealed_seed_digest;

use crate::keys::MASTER_SEED_LEN;

/// Outlives every release, so it changes only with the blob's own layout.
const FORMAT_VERSION: u8 = 1;

/// The wire bytes. The Quorum key signs the ciphertext, since anyone can encrypt to it.
#[derive(BorshSerialize, BorshDeserialize)]
struct SealedMasterSeed {
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

/// The ciphertext's contents, which pin the seed to a Quorum key epoch and network.
#[derive(BorshSerialize, BorshDeserialize)]
struct UnsealedMasterSeed {
    version: u8,
    quorum_key_id: String,
    quorum_key_epoch: u64,
    network: String,
    seed: [u8; MASTER_SEED_LEN],
}

impl Drop for UnsealedMasterSeed {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

fn signed(ciphertext: &[u8]) -> Vec<u8> {
    [MASTER_SEED_SIGNATURE_DOMAIN, ciphertext].concat()
}

/// Seals `seed` for the running release, signed by `signer`.
fn seal(
    service: &Service,
    seed: &[u8; MASTER_SEED_LEN],
    signer: &P256Pair,
) -> Result<Vec<u8>, Failure> {
    let info = &service.info;
    let contents = UnsealedMasterSeed {
        version: FORMAT_VERSION,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        network: info.network.as_str().to_owned(),
        seed: *seed,
    };
    let plaintext = Zeroizing::new(borsh::to_vec(&contents).map_err(|_| Failure::Unavailable)?);
    let ciphertext = service
        .quorum
        .public_key()
        .encrypt(&plaintext)
        .map_err(|_| Failure::Unavailable)?;
    let signature = signer
        .sign(&signed(&ciphertext))
        .map_err(|_| Failure::Unavailable)?;
    borsh::to_vec(&SealedMasterSeed {
        ciphertext,
        signature,
    })
    .map_err(|_| Failure::Unavailable)
}

/// Draws a master seed and seals it. Returns the wire bytes and their digest.
pub(crate) fn generate(service: &Service) -> Result<(Vec<u8>, [u8; 32]), Failure> {
    let mut seed = Zeroizing::new([0; MASTER_SEED_LEN]);
    UnwrapErr(OsRng).fill_bytes(seed.as_mut_slice());
    let bytes = seal(service, &seed, &service.quorum)?;
    let digest = sealed_seed_digest(&bytes);
    Ok((bytes, digest))
}

/// What anyone can build from the public Quorum key: a known seed, sealed.
#[cfg(test)]
pub(crate) fn forged(service: &Service, seed: [u8; MASTER_SEED_LEN]) -> Vec<u8> {
    seal(service, &seed, &P256Pair::generate().unwrap()).unwrap()
}

/// Opens a blob this release's Quorum key signed. Returns the seed and the blob's digest.
pub(crate) fn unseal(
    bytes: &[u8],
    service: &Service,
) -> Result<(Zeroizing<[u8; MASTER_SEED_LEN]>, [u8; 32]), Failure> {
    let info = &service.info;
    let quorum = &service.quorum;
    let sealed = SealedMasterSeed::try_from_slice(bytes).map_err(|_| Failure::Invalid)?;
    quorum
        .public_key()
        .verify(&signed(&sealed.ciphertext), &sealed.signature)
        .map_err(|_| Failure::Invalid)?;
    let plaintext = Zeroizing::new(
        quorum
            .decrypt(&sealed.ciphertext)
            .map_err(|_| Failure::Invalid)?,
    );
    let contents = UnsealedMasterSeed::try_from_slice(&plaintext).map_err(|_| Failure::Invalid)?;
    if contents.version != FORMAT_VERSION
        || contents.quorum_key_id != info.quorum_key_id
        || contents.quorum_key_epoch != info.quorum_key_epoch
        || contents.network != info.network.as_str()
    {
        return Err(Failure::Invalid);
    }
    Ok((Zeroizing::new(contents.seed), sealed_seed_digest(bytes)))
}
