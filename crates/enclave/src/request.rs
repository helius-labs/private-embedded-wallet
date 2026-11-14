//! The encrypted request every operation arrives in, and its proof-carrying answer.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use p256::ecdsa::Signature;
use qos_p256::P256Pair;
use serde::Serialize;
use spr_tvc_protocol::constants::{
    API_VERSION, MAX_ENCRYPTED_RESPONSE_BYTES, TVC_APP_PROOF_SCHEME,
};
use spr_tvc_protocol::crypto::qos_encrypt;
use spr_tvc_protocol::digest::result_digest;
use spr_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use spr_tvc_protocol::types::{
    parse_encrypted_request, AppProof, EncryptedResponse, OperationKind, OperationProofPayload,
    ServiceInfo, WalletGrant,
};
use zeroize::Zeroizing;

use crate::http::PublicError;

/// Why a request got no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Malformed or not authorized; a generic 400.
    Invalid,
    /// The enclave cannot serve; a generic 503.
    Unavailable,
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::Invalid => PublicError::InvalidRequest,
            Self::Unavailable => PublicError::Unavailable,
        }
        .into_response()
    }
}

/// Opens a request's envelope. Returns its grant and its canonical JSON plaintext.
pub fn open_envelope(
    info: &ServiceInfo,
    quorum: &P256Pair,
    body: &[u8],
) -> Result<(Option<WalletGrant>, Zeroizing<String>), Failure> {
    let body = std::str::from_utf8(body).map_err(|_| Failure::Invalid)?;
    let encrypted = parse_encrypted_request(body).map_err(|_| Failure::Invalid)?;
    if encrypted.version != API_VERSION
        || encrypted.quorum_key_id != info.quorum_key_id
        || encrypted.quorum_key_epoch != info.quorum_key_epoch
    {
        return Err(Failure::Invalid);
    }
    let plaintext = Zeroizing::new(
        quorum
            .decrypt(&encrypted.ciphertext)
            .map_err(|_| Failure::Invalid)?,
    );
    let plaintext = std::str::from_utf8(&plaintext).map_err(|_| Failure::Invalid)?;
    if !is_rfc8785(plaintext) {
        return Err(Failure::Invalid);
    }
    Ok((encrypted.wallet_grant, Zeroizing::new(plaintext.to_owned())))
}

/// What an App Proof binds a result to.
pub struct ProofBinding {
    pub proof_type: &'static str,
    pub request_id: [u8; 32],
    pub request_digest: [u8; 32],
    pub operation: OperationKind,
    pub sealed_seed_digest: [u8; 32],
}

/// Encrypts `result` to the response key under an App Proof the Ephemeral key signs.
pub fn respond<T: Serialize>(
    ephemeral: &P256Pair,
    binding: ProofBinding,
    client_response_public_key: &[u8],
    result: &T,
) -> Result<String, Failure> {
    let plaintext = Zeroizing::new(jcs_serialize(result).map_err(|_| Failure::Unavailable)?);
    let encrypted_result = qos_encrypt(client_response_public_key, plaintext.as_bytes())
        .map_err(|_| Failure::Unavailable)?;
    if encrypted_result.len() as u64 > MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(Failure::Unavailable);
    }

    let proof_payload = jcs_serialize(&OperationProofPayload {
        r#type: binding.proof_type.to_owned(),
        version: API_VERSION,
        request_id: binding.request_id,
        request_digest: binding.request_digest,
        result_digest: result_digest(&encrypted_result),
        operation: binding.operation,
        sealed_seed_digest: binding.sealed_seed_digest,
    })
    .map_err(|_| Failure::Unavailable)?;
    let signature = sign_ephemeral_low_s(ephemeral, proof_payload.as_bytes())?;
    jcs_serialize(&EncryptedResponse {
        version: API_VERSION,
        request_id: binding.request_id,
        encrypted_result,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: ephemeral.public_key().to_bytes(),
            proof_payload,
            signature,
        },
    })
    .map_err(|_| Failure::Unavailable)
}

pub(crate) fn sign_ephemeral_low_s(
    ephemeral: &P256Pair,
    message: &[u8],
) -> Result<Vec<u8>, Failure> {
    let raw = ephemeral.sign(message).map_err(|_| Failure::Unavailable)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Failure::Unavailable)?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    Ok(normalized.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

    #[test]
    fn qos_signatures_are_normalized_to_low_s_for_the_wire() {
        let message = b"spr tvc low-s interop";
        for seed_byte in 0u8..=u8::MAX {
            let pair = P256Pair::from_master_seed(&Zeroizing::new([seed_byte; 32])).unwrap();
            let raw = pair.sign(message).unwrap();
            let raw = Signature::from_slice(&raw).unwrap();
            if raw.normalize_s().is_some() {
                let normalized = sign_ephemeral_low_s(&pair, message).unwrap();
                let normalized = Signature::from_slice(&normalized).unwrap();
                assert!(normalized.normalize_s().is_none());
                pair.public_key()
                    .verify(message, &normalized.to_bytes())
                    .unwrap();
                return;
            }
        }
        panic!("fixed QOS seed corpus did not produce a high-S signature");
    }
}
