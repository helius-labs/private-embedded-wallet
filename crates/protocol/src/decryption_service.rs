//! The decryption service: requests, results and the messages an owner signs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::digest::domain_separated_hash;
use crate::encoding::{self, canonicalize_json_value, decimal_u64, encode_lower_hex, hex};
use crate::error::{ErrorCode, TvcError};
use crate::types::{DecryptItem, Network, OperationKind};

pub const SERVICE_PROOF_TYPE: &str = "spr.tvc.decryption_service.v1";
pub const SERVICE_REQUEST_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";
/// What the Quorum key signs, before the sealed master seed's ciphertext.
pub const MASTER_SEED_SIGNATURE_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_SEED_V1";

/// Label of the message that authorizes a `Decrypt`.
pub const DECRYPT_LABEL: &str = "TSPP/decryption-service/decrypt/v1";

pub const ADDRESS_LEN: usize = 32;
pub const X25519_PUBLIC_KEY_LEN: usize = 33;
pub const NULLIFIER_SECRET_LEN: usize = 31;

const OFFCHAIN_MESSAGE_MAGIC: &[u8; 16] = b"\xffsolana offchain";

/// The plaintext of an `EncryptedRequest` to the decryption service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    pub target_release_id: String,
    #[serde(with = "hex")]
    pub target_manifest_digest: [u8; 32],
    #[serde(with = "hex")]
    pub target_executable_digest: [u8; 32],
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    /// Absent on `Genesis`, required otherwise.
    #[serde(with = "hex")]
    pub sealed_master_seed: Option<Vec<u8>>,
    #[serde(with = "hex")]
    pub client_response_public_key: Vec<u8>,
    pub operation: ServiceOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServiceOperation {
    /// Draws a master seed and seals it to the Quorum key.
    Genesis,
    /// The service public keys of a base58 address.
    PublicKeys { address: String },
    /// Opens `items`; `signature` is the base58 `signer`'s, over [`decrypt_message`].
    Decrypt {
        signer: String,
        #[serde(with = "hex")]
        signature: [u8; 64],
        items: Vec<DecryptItem>,
    },
}

impl ServiceOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Genesis => OperationKind::ServiceGenesis,
            Self::PublicKeys { .. } => OperationKind::ServicePublicKeys,
            Self::Decrypt { .. } => OperationKind::ServiceDecrypt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServiceResult {
    Genesis {
        #[serde(with = "hex")]
        sealed_master_seed: Vec<u8>,
    },
    PublicKeys {
        #[serde(with = "hex")]
        viewing_public_key: [u8; X25519_PUBLIC_KEY_LEN],
        #[serde(with = "hex")]
        nullifier_public_key: [u8; 32],
    },
    Decrypt(DecryptedOutputs),
}

/// One plaintext per item, in order, and the secret that spends them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DecryptedOutputs {
    #[serde(with = "hex")]
    pub nullifier_secret: [u8; NULLIFIER_SECRET_LEN],
    #[serde(with = "hex")]
    pub plaintexts: Vec<Vec<u8>>,
}

impl std::fmt::Debug for DecryptedOutputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecryptedOutputs(..)")
    }
}

pub fn parse_service_request(json: &str) -> Result<ServiceRequest, TvcError> {
    encoding::parse_strict_json(json)
}

/// `H(SERVICE_REQUEST_DIGEST_DOMAIN, JCS(request))`, without a `Decrypt`'s signature.
pub fn service_request_digest(request: &ServiceRequest) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(request)?;
    value
        .get_mut("operation")
        .and_then(|operation| operation.as_object_mut())
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?
        .remove("signature");
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        SERVICE_REQUEST_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// What an owner signs for one `Decrypt`: a Solana off-chain message v0 with one signer.
pub fn decrypt_message(
    signer: &[u8; ADDRESS_LEN],
    network: Network,
    request_digest: &[u8; 32],
) -> Vec<u8> {
    let payload = format!(
        "{DECRYPT_LABEL}/{network}/{}",
        encode_lower_hex(request_digest)
    );
    let length = u16::try_from(payload.len()).expect("the payload is short");
    let mut message = Vec::with_capacity(85 + payload.len());
    message.extend_from_slice(OFFCHAIN_MESSAGE_MAGIC);
    message.push(0);
    message.extend_from_slice(&Sha256::digest(DECRYPT_LABEL.as_bytes()));
    message.push(0);
    message.push(1);
    message.extend_from_slice(signer);
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(payload.as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DecryptLabel;

    fn request(operation: ServiceOperation) -> ServiceRequest {
        ServiceRequest {
            version: 1,
            request_id: [1; 32],
            target_release_id: "release".to_owned(),
            target_manifest_digest: [2; 32],
            target_executable_digest: [3; 32],
            quorum_key_id: "quorum".to_owned(),
            quorum_key_epoch: 1,
            sealed_master_seed: None,
            client_response_public_key: vec![4; 65],
            operation,
        }
    }

    fn decrypt(signature: [u8; 64], slot_index: u64) -> ServiceOperation {
        ServiceOperation::Decrypt {
            signer: "11111111111111111111111111111111".to_owned(),
            signature,
            items: vec![DecryptItem {
                ciphertext: vec![1, 2, 3],
                viewing_public_key: vec![4; 33],
                transaction_viewing_public_key: vec![4; 33],
                salt: vec![0; 16],
                slot_index,
                label: DecryptLabel::Transfer,
            }],
        }
    }

    #[test]
    fn the_decrypt_message_is_a_solana_offchain_message() {
        let message = decrypt_message(&[7; 32], Network::Mainnet, &[9; 32]);
        let payload = format!(
            "TSPP/decryption-service/decrypt/v1/mainnet/{}",
            "09".repeat(32)
        );
        let mut expected = b"\xffsolana offchain\0".to_vec();
        expected.extend_from_slice(&Sha256::digest(b"TSPP/decryption-service/decrypt/v1"));
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        expected.extend_from_slice(payload.as_bytes());
        assert_eq!(message, expected);
        assert_ne!(
            message,
            decrypt_message(&[7; 32], Network::Devnet, &[9; 32]),
            "a message names its network"
        );
    }

    #[test]
    fn the_request_digest_covers_everything_but_the_signature() {
        let digest = service_request_digest(&request(decrypt([0; 64], 0))).unwrap();
        assert_eq!(
            digest,
            service_request_digest(&request(decrypt([1; 64], 0))).unwrap()
        );
        assert_ne!(
            digest,
            service_request_digest(&request(decrypt([0; 64], 1))).unwrap()
        );
        let mut other_key = request(decrypt([0; 64], 0));
        other_key.client_response_public_key = vec![5; 65];
        assert_ne!(digest, service_request_digest(&other_key).unwrap());
    }

    #[test]
    fn a_request_parses_strictly() {
        let request = request(ServiceOperation::PublicKeys {
            address: "11111111111111111111111111111111".to_owned(),
        });
        let json = encoding::jcs_serialize(&request).unwrap();
        assert_eq!(parse_service_request(&json).unwrap(), request);
        assert!(parse_service_request(&json.replacen('{', r#"{"extra":1,"#, 1)).is_err());
    }
}
