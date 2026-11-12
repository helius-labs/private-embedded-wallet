//! The decryption service: requests, results and the messages an owner signs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::digest::domain_separated_hash;
use crate::encoding::{self, decimal_u64, encode_lower_hex, hex};
use crate::error::TvcError;
use crate::types::{DecryptItem, Network, OperationKind};

pub const SERVICE_PATH: &str = "/v1/decryption-service";
pub const SERVICE_PROOF_TYPE: &str = "spr.tvc.decryption_service.v1";
pub const SERVICE_REQUEST_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";
pub const DECRYPT_ITEMS_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_ITEMS_V1";

/// Label of the message that authorizes a `Decrypt`, and of one for a `Claim`.
pub const DECRYPT_LABEL: &str = "TSPP/decryption-service/decrypt/v1";
pub const CLAIM_LABEL: &str = "TSPP/decryption-service/claim/v1";
/// HPKE info of a `Decrypt` answer, and of a `Claim` answer.
pub const SEALED_OUTPUTS_INFO: &[u8] = b"TSPP/decryption-service/sealed_outputs/v1";
pub const SEALED_KEYS_INFO: &[u8] = b"TSPP/decryption-service/sealed_keys/v1";

pub const ADDRESS_LEN: usize = 32;
pub const X25519_PUBLIC_KEY_LEN: usize = 33;
pub const VIEWING_SECRET_LEN: usize = 32;
pub const NULLIFIER_SECRET_LEN: usize = 31;

const OFFCHAIN_MESSAGE_MAGIC: &[u8; 16] = b"\xffsolana offchain";

/// The plaintext of an `EncryptedRequest` posted to [`SERVICE_PATH`].
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

/// The owner of the base58 `signer` lets `wallet_viewing_public_key` read an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAuthorization {
    pub signer: String,
    #[serde(with = "hex")]
    pub wallet_viewing_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    #[serde(with = "hex")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServiceOperation {
    /// Draws a master seed and seals it to the Quorum key.
    Genesis,
    /// The service public keys of a base58 address.
    PublicKeys { address: String },
    /// Opens `items` with the signer's service viewing key.
    Decrypt {
        authorization: OwnerAuthorization,
        items: Vec<DecryptItem>,
    },
    /// Releases the signer's service secrets.
    Claim { authorization: OwnerAuthorization },
}

impl ServiceOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Genesis => OperationKind::ServiceGenesis,
            Self::PublicKeys { .. } => OperationKind::ServicePublicKeys,
            Self::Decrypt { .. } => OperationKind::ServiceDecrypt,
            Self::Claim { .. } => OperationKind::ServiceClaim,
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
    /// The answer to a `Decrypt` or a `Claim`, HPKE to the authorized viewing key.
    Sealed {
        #[serde(with = "hex")]
        enc: [u8; 32],
        #[serde(with = "hex")]
        ciphertext: Vec<u8>,
    },
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

pub fn parse_service_request(json: &str) -> Result<ServiceRequest, TvcError> {
    encoding::parse_strict_json(json)
}

/// `H(SERVICE_REQUEST_DIGEST_DOMAIN, JCS(request))`.
pub fn service_request_digest(request: &ServiceRequest) -> Result<[u8; 32], TvcError> {
    let canonical = encoding::jcs_serialize(request)?;
    Ok(domain_separated_hash(
        SERVICE_REQUEST_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// `H(DECRYPT_ITEMS_DIGEST_DOMAIN, JCS(items))`.
pub fn decrypt_items_digest(items: &[DecryptItem]) -> Result<[u8; 32], TvcError> {
    let canonical = encoding::jcs_serialize(&items)?;
    Ok(domain_separated_hash(
        DECRYPT_ITEMS_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// A Solana off-chain message v0, format 0, one signer, domain `SHA-256(label)`.
fn owner_message(
    label: &str,
    signer: &[u8; ADDRESS_LEN],
    network: Network,
    wallet_viewing_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    items_digest: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = format!(
        "{label}/{network}/{}",
        encode_lower_hex(wallet_viewing_public_key)
    );
    if let Some(digest) = items_digest {
        payload.push('/');
        payload.push_str(&encode_lower_hex(digest));
    }
    let length = u16::try_from(payload.len()).expect("the payload is short");
    let mut message = Vec::with_capacity(85 + payload.len());
    message.extend_from_slice(OFFCHAIN_MESSAGE_MAGIC);
    message.push(0);
    message.extend_from_slice(&Sha256::digest(label.as_bytes()));
    message.push(0);
    message.push(1);
    message.extend_from_slice(signer);
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(payload.as_bytes());
    message
}

/// What an owner signs to have one batch opened for a wallet viewing key.
pub fn decrypt_message(
    signer: &[u8; ADDRESS_LEN],
    network: Network,
    wallet_viewing_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    items_digest: &[u8; 32],
) -> Vec<u8> {
    owner_message(
        DECRYPT_LABEL,
        signer,
        network,
        wallet_viewing_public_key,
        Some(items_digest),
    )
}

/// What an owner signs to release the service secrets to a wallet viewing key.
pub fn claim_message(
    signer: &[u8; ADDRESS_LEN],
    network: Network,
    wallet_viewing_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Vec<u8> {
    owner_message(
        CLAIM_LABEL,
        signer,
        network,
        wallet_viewing_public_key,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DecryptLabel;

    fn item(slot_index: u64) -> DecryptItem {
        DecryptItem {
            ciphertext: vec![1, 2, 3],
            viewing_public_key: vec![4; 33],
            transaction_viewing_public_key: vec![4; 33],
            salt: vec![0; 16],
            slot_index,
            label: DecryptLabel::Transfer,
        }
    }

    #[test]
    fn owner_messages_are_solana_offchain_messages() {
        let digest = decrypt_items_digest(&[item(0)]).unwrap();
        let message = decrypt_message(&[7; 32], Network::Mainnet, &[4; 33], &digest);
        let payload = format!(
            "TSPP/decryption-service/decrypt/v1/mainnet/{}/{}",
            "04".repeat(33),
            encode_lower_hex(&digest)
        );
        let mut expected = b"\xffsolana offchain\0".to_vec();
        expected.extend_from_slice(&Sha256::digest(b"TSPP/decryption-service/decrypt/v1"));
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        expected.extend_from_slice(payload.as_bytes());
        assert_eq!(message, expected);

        let claim = claim_message(&[7; 32], Network::Mainnet, &[4; 33]);
        assert!(claim.ends_with(
            format!(
                "TSPP/decryption-service/claim/v1/mainnet/{}",
                "04".repeat(33)
            )
            .as_bytes()
        ));
        assert_ne!(
            claim[17..49],
            message[17..49],
            "separate application domains"
        );
        assert_ne!(
            claim,
            claim_message(&[7; 32], Network::Devnet, &[4; 33]),
            "a message names its network"
        );
    }

    #[test]
    fn the_items_digest_covers_content_and_order() {
        let digest = decrypt_items_digest(&[item(0), item(1)]).unwrap();
        assert_ne!(digest, decrypt_items_digest(&[item(1), item(0)]).unwrap());
        assert_ne!(digest, decrypt_items_digest(&[item(0)]).unwrap());
    }

    #[test]
    fn a_request_parses_strictly_and_digests_canonically() {
        let request = ServiceRequest {
            version: 1,
            request_id: [1; 32],
            target_release_id: "release".to_owned(),
            target_manifest_digest: [2; 32],
            target_executable_digest: [3; 32],
            quorum_key_id: "quorum".to_owned(),
            quorum_key_epoch: 1,
            sealed_master_seed: None,
            client_response_public_key: vec![4; 65],
            operation: ServiceOperation::PublicKeys {
                address: "11111111111111111111111111111111".to_owned(),
            },
        };
        let json = encoding::jcs_serialize(&request).unwrap();
        assert_eq!(parse_service_request(&json).unwrap(), request);
        assert!(parse_service_request(&json.replacen('{', r#"{"extra":1,"#, 1)).is_err());

        let mut other = request.clone();
        other.operation = ServiceOperation::Genesis;
        assert_ne!(
            service_request_digest(&request).unwrap(),
            service_request_digest(&other).unwrap()
        );
    }
}
