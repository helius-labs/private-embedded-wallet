//! The encrypted operation endpoint.
//!
//! The enclave is a stateless oracle over the wallet's privacy roles. It holds
//! the derivation seed only for one request, unsealed from the blob the client
//! presents, and stores nothing across requests. Only bootstrap reaches the
//! custodian; every other operation needs nothing but the seed. `Prove` seals
//! the completed witness to an attested prover and reaches no service: the
//! client posts the sealed request.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use solana_pubkey::Pubkey;
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_CLOCK_SKEW_MS, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_REQUEST_AGE_MS,
    TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{parse_uncompressed_sec1, qos_encrypt, verify_p256_prehash};
use zolana_tvc_protocol::digest::{descriptor_digest, request_digest, result_digest};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, AppProof, EncryptedResponse, FailureStage,
    Operation, OperationKind, OperationProofPayload, OperationRequest, OperationResult,
};
use zolana_tvc_protocol::{client_key_id, verify_wallet_grant};

use self::bindings::{check_encrypted_request_bindings, check_request_bindings};
use crate::custody::{CustodyError, WalletKey};
use crate::http::{self, PublicError};
use crate::{sign_ephemeral_low_s, AppState};

mod bindings;
mod bootstrap;
mod keys;
mod prove;
mod sealed;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "local-dev"))]
pub(crate) use prove::sign_policy;
pub(crate) use prove::ProverTrust;

/// Every operation this application serves. A descriptor grants the whole set.
pub const OPERATIONS: [OperationKind; 5] = [
    OperationKind::Bootstrap,
    OperationKind::Decrypt,
    OperationKind::Derive,
    OperationKind::TransactionKeys,
    OperationKind::Prove,
];

const DERIVATION_SUITE: &str = "zolana-ed25519-role-expansion-v1";
/// Leave time to respond before the proxy deadline; request expiry may shorten this.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(75);

/// How an operation did not produce a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The request is malformed or not authorized; answered with a generic 400.
    Invalid,
    /// The enclave cannot serve; answered with a generic 503.
    Unavailable,
    /// The operation ran and failed at a named stage; answered inside the
    /// encrypted result so only the requester learns which.
    Stage(FailureStage),
}

impl From<CustodyError> for Failure {
    fn from(error: CustodyError) -> Self {
        match error {
            CustodyError::Unavailable => Self::Unavailable,
            CustodyError::Declined => Self::Stage(FailureStage::TurnkeySigning),
        }
    }
}

pub(crate) async fn handle(state: &AppState, body: &[u8]) -> Response<Body> {
    match execute(state, body).await {
        Ok(response) => http::ok(response),
        Err(Failure::Invalid) => PublicError::InvalidRequest.into_response(),
        Err(Failure::Unavailable | Failure::Stage(_)) => PublicError::Unavailable.into_response(),
    }
}

async fn execute(state: &AppState, body: &[u8]) -> Result<String, Failure> {
    let runtime = &state.runtime;
    let body = std::str::from_utf8(body).map_err(|_| Failure::Invalid)?;
    let encrypted = parse_encrypted_request(body).map_err(|_| Failure::Invalid)?;
    check_encrypted_request_bindings(&encrypted, &state.info).map_err(|_| Failure::Invalid)?;

    let plaintext = Zeroizing::new(
        runtime
            .quorum
            .decrypt(&encrypted.ciphertext)
            .map_err(|_| Failure::Invalid)?,
    );
    let plaintext = std::str::from_utf8(&plaintext).map_err(|_| Failure::Invalid)?;
    if !is_rfc8785(plaintext) {
        return Err(Failure::Invalid);
    }
    let request = parse_operation_request(plaintext).map_err(|_| Failure::Invalid)?;
    let wallet = validate(&request, state)?;
    let grant = encrypted.wallet_grant.as_ref().ok_or(Failure::Invalid)?;
    verify_wallet_grant(
        grant,
        &runtime.grant_public,
        &request.wallet_descriptor,
        &request.authorization.client_key_id,
        now_ms()?,
    )
    .map_err(|_| Failure::Invalid)?;
    let request_hash = request_digest(&request).map_err(|_| Failure::Invalid)?;
    parse_uncompressed_sec1(&request.client_response_public_key).map_err(|_| Failure::Invalid)?;

    // Every result carries the digest of the sealed seed it was computed
    // against, so the App Proof binds the answer to one seed, not merely
    // to the request.
    let (result, proof_seed_digest) = match &request.operation {
        Operation::Bootstrap => {
            let until_expiry =
                Duration::from_millis(request.expires_at_ms.saturating_sub(now_ms()?));
            tokio::time::timeout(
                OPERATION_TIMEOUT.min(until_expiry),
                bootstrap::run(&request, &wallet, runtime),
            )
            .await
            .map_err(|_| Failure::Unavailable)??
        }
        Operation::Decrypt { items } => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            (keys::decrypt(&roles, items)?, digest)
        }
        Operation::Derive { items } => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            (keys::derive(&roles, items)?, digest)
        }
        Operation::TransactionKeys { items } => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            (keys::transaction_keys(&roles, items)?, digest)
        }
        Operation::Prove {
            request: body,
            prover,
        } => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            let result = match prove::seal(
                body,
                roles.nullifier_key.secret().as_slice(),
                prover,
                &runtime.prover,
                now_ms()?,
            ) {
                Ok(sealed) => OperationResult::Prove { sealed },
                Err(Failure::Stage(stage)) => OperationResult::Failure {
                    operation: OperationKind::Prove,
                    stage,
                },
                Err(failure) => return Err(failure),
            };
            (result, digest)
        }
    };

    let result_plaintext =
        Zeroizing::new(jcs_serialize(&result).map_err(|_| Failure::Unavailable)?);
    let encrypted_result = qos_encrypt(
        &request.client_response_public_key,
        result_plaintext.as_bytes(),
    )
    .map_err(|_| Failure::Unavailable)?;
    if encrypted_result.len() as u64 > MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(Failure::Unavailable);
    }

    let proof_payload = jcs_serialize(&OperationProofPayload {
        r#type: TVC_APP_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: request.request_id,
        request_digest: request_hash,
        result_digest: result_digest(&encrypted_result),
        operation: request.operation.kind(),
        sealed_seed_digest: proof_seed_digest,
    })
    .map_err(|_| Failure::Unavailable)?;
    let signature = sign_ephemeral_low_s(&runtime.ephemeral, proof_payload.as_bytes())
        .map_err(|_| Failure::Unavailable)?;
    jcs_serialize(&EncryptedResponse {
        version: API_VERSION,
        request_id: request.request_id,
        encrypted_result,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: runtime.ephemeral.public_key().to_bytes(),
            proof_payload,
            signature,
        },
    })
    .map_err(|_| Failure::Unavailable)
}

/// Binds the request to this release, checks its freshness, verifies the
/// provisioner's signature over the descriptor and the client's signature over
/// the request, and returns the Turnkey key the descriptor names.
fn validate<'a>(request: &'a OperationRequest, state: &AppState) -> Result<WalletKey<'a>, Failure> {
    // Also refuses a descriptor for another network and an empty Turnkey wallet ID.
    check_request_bindings(request, &state.info).map_err(|_| Failure::Invalid)?;
    let kind = request.operation.kind();
    // Bootstrap derives a fresh state; every other operation answers against
    // the presented one.
    let expects_seed = kind != OperationKind::Bootstrap;
    if !state.info.supported_operations.contains(&kind)
        || request.sealed_seed.is_some() != expects_seed
    {
        return Err(Failure::Invalid);
    }

    let now = now_ms()?;
    if request.expires_at_ms < now
        || request.issued_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || request.expires_at_ms < request.issued_at_ms
        || request.expires_at_ms - request.issued_at_ms > MAX_REQUEST_AGE_MS
    {
        return Err(Failure::Invalid);
    }

    let descriptor = &request.wallet_descriptor;
    let address = Pubkey::from_str(&descriptor.address).map_err(|_| Failure::Invalid)?;
    if descriptor.version != API_VERSION
        || !is_canonical_uuid(&descriptor.turnkey_organization_id)
        || descriptor.turnkey_wallet_id.len() > 128
        || descriptor.allowed_clients.len() != 1
    {
        return Err(Failure::Invalid);
    }
    let digest = descriptor_digest(descriptor).map_err(|_| Failure::Invalid)?;
    verify_p256_prehash(
        &state.runtime.provisioning_public,
        &digest,
        &descriptor.provisioning_signature,
    )
    .map_err(|_| Failure::Invalid)?;

    let grant = &descriptor.allowed_clients[0];
    if grant.client_public_key.len() != 65
        || grant.allowed_operations != OPERATIONS
        || request.authorization.client_key_id != client_key_id(&grant.client_public_key)
    {
        return Err(Failure::Invalid);
    }
    zolana_tvc_protocol::verify_client_authorization(request, &grant.client_public_key)
        .map_err(|_| Failure::Invalid)?;

    Ok(WalletKey {
        organization_id: &descriptor.turnkey_organization_id,
        sign_with: &descriptor.address,
        public_key: address.to_bytes(),
    })
}

fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

fn now_ms() -> Result<u64, Failure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Unavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| Failure::Unavailable)
}
