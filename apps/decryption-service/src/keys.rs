//! The service keys of an address.

use hkdf::Hkdf;
use sha2::Sha256;
use spr_keypair::{NullifierKey, ViewingKey};
use zeroize::Zeroizing;
use zolana_tvc_protocol::decryption_service::{ADDRESS_LEN, NULLIFIER_SECRET_LEN};

const VIEWING_KEY_LABEL: &[u8] = b"TSPP/decryption-service/view_key/x25519/v1";
const NULLIFIER_KEY_LABEL: &[u8] = b"TSPP/decryption-service/nf_key/v1";

pub(crate) const MASTER_SEED_LEN: usize = 32;

pub(crate) struct ServiceKeys {
    pub viewing: ViewingKey,
    pub nullifier: NullifierKey,
}

/// HKDF-SHA256 over the master seed, one Expand per key with the address in the info.
pub(crate) fn derive(seed: &[u8; MASTER_SEED_LEN], address: &[u8; ADDRESS_LEN]) -> ServiceKeys {
    let hkdf = Hkdf::<Sha256>::new(None, seed);
    let mut viewing = Zeroizing::new([0u8; 32]);
    hkdf.expand_multi_info(&[VIEWING_KEY_LABEL, address], viewing.as_mut_slice())
        .expect("32 bytes of output");
    let mut nullifier = Zeroizing::new([0u8; NULLIFIER_SECRET_LEN]);
    hkdf.expand_multi_info(&[NULLIFIER_KEY_LABEL, address], nullifier.as_mut_slice())
        .expect("31 bytes of output");
    ServiceKeys {
        // Clamps, so the secret has one byte string.
        viewing: ViewingKey::from_bytes(&viewing),
        nullifier: NullifierKey::from_secret(*nullifier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_separate_addresses_and_seeds() {
        let keys = derive(&[7; 32], &[1; 32]);
        let other_address = derive(&[7; 32], &[2; 32]);
        let other_seed = derive(&[8; 32], &[1; 32]);
        for other in [other_address, other_seed] {
            assert_ne!(keys.viewing.secret_bytes(), other.viewing.secret_bytes());
            assert_ne!(keys.nullifier.secret(), other.nullifier.secret());
        }
    }

    /// Pins the derivation; checked against an independent HKDF and X25519.
    #[test]
    fn derivation_vectors() {
        let keys = derive(&[0x5a; 32], &[0x11; 32]);
        assert_eq!(
            [
                hex::encode(keys.viewing.secret_bytes().as_slice()),
                hex::encode(keys.viewing.pubkey().as_bytes()),
                hex::encode(keys.nullifier.secret().as_slice()),
                hex::encode(keys.nullifier.pubkey().unwrap()),
            ],
            [
                "705f5cdb4710d0ec61f3c31de8ab02aca7e7ed958fec7eb07fe99b4e67c7c24e",
                "0402822462ef6f30c21475fb5ad701e4de02c6ab4074065947e28573b5746a5578",
                "35236554a7963d61dcccaa23074d5f27e5e0e2295f055c54fcc8f66b767e4d",
                "0cc1419c0a0cad87eae0f0708e01227c8ae90c43581c4965f40cab6157fcce8a",
            ]
        );
    }
}
