//! The decryption service: service keys for addresses without a registered wallet.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::parse_uncompressed_sec1;
use zolana_tvc_protocol::decryption_service::{
    claim_message, decrypt_items_digest, decrypt_message, parse_service_request,
    service_request_digest, DecryptedOutputs, ServiceOperation, ServiceRequest, ServiceResult,
    SEALED_KEYS_INFO, SEALED_OUTPUTS_INFO, SERVICE_PROOF_TYPE,
};
use zolana_tvc_protocol::encoding::jcs_serialize;
use zolana_tvc_protocol::types::OperationProofPayload;

use crate::http::{self, PublicError};
use crate::operations::{open_ciphertexts, open_envelope, respond, Failure};
use crate::AppState;

mod keys;
mod owner;
mod seed;
#[cfg(test)]
mod tests;

pub(crate) fn handle(state: &AppState, body: &[u8]) -> Response<Body> {
    match execute(state, body) {
        Ok(response) => http::ok(response),
        Err(Failure::Invalid) => PublicError::InvalidRequest.into_response(),
        Err(_) => PublicError::Unavailable.into_response(),
    }
}

fn execute(state: &AppState, body: &[u8]) -> Result<String, Failure> {
    let (grant, plaintext) = open_envelope(state, body)?;
    let request = parse_service_request(&plaintext).map_err(|_| Failure::Invalid)?;
    if grant.is_some() || !targets_running_release(&request, state) {
        return Err(Failure::Invalid);
    }
    parse_uncompressed_sec1(&request.client_response_public_key).map_err(|_| Failure::Invalid)?;

    let (result, sealed_seed_digest) = run(&request, state)?;
    respond(
        &state.runtime,
        OperationProofPayload {
            r#type: SERVICE_PROOF_TYPE.to_owned(),
            version: API_VERSION,
            request_id: request.request_id,
            request_digest: service_request_digest(&request).map_err(|_| Failure::Invalid)?,
            result_digest: [0; 32],
            operation: request.operation.kind(),
            sealed_seed_digest,
        },
        &request.client_response_public_key,
        &result,
    )
}

fn targets_running_release(request: &ServiceRequest, state: &AppState) -> bool {
    let info = &state.info;
    request.version == API_VERSION
        && request.target_release_id == info.release_id
        && request.target_manifest_digest == info.manifest_digest
        && request.target_executable_digest == info.executable_digest
        && request.quorum_key_id == info.quorum_key_id
        && request.quorum_key_epoch == info.quorum_key_epoch
}

/// Returns the result and the digest of the sealed master seed it came from.
fn run(request: &ServiceRequest, state: &AppState) -> Result<(ServiceResult, [u8; 32]), Failure> {
    let network = state.info.network;
    let presented = request.sealed_master_seed.as_deref();
    let unseal = || seed::unseal(presented.ok_or(Failure::Invalid)?, state);
    match &request.operation {
        ServiceOperation::Genesis => {
            if presented.is_some() {
                return Err(Failure::Invalid);
            }
            let (sealed_master_seed, digest) = seed::generate(state)?;
            Ok((ServiceResult::Genesis { sealed_master_seed }, digest))
        }
        ServiceOperation::PublicKeys { address } => {
            let (seed, digest) = unseal()?;
            let keys = keys::derive(&seed, &owner::signer(address)?.to_bytes());
            let result = ServiceResult::PublicKeys {
                viewing_public_key: *keys.viewing.pubkey().as_bytes(),
                nullifier_public_key: keys.nullifier.pubkey().map_err(|_| Failure::Unavailable)?,
            };
            Ok((result, digest))
        }
        ServiceOperation::Decrypt {
            authorization,
            items,
        } => {
            let (seed, digest) = unseal()?;
            let batch = decrypt_items_digest(items).map_err(|_| Failure::Invalid)?;
            let signer = owner::authorized(authorization, |signer| {
                decrypt_message(
                    signer,
                    network,
                    &authorization.wallet_viewing_public_key,
                    &batch,
                )
            })?;
            let keys = keys::derive(&seed, &signer);
            let outputs = DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts: open_ciphertexts(&keys.viewing, items)?,
            };
            let outputs =
                Zeroizing::new(jcs_serialize(&outputs).map_err(|_| Failure::Unavailable)?);
            let aad = [signer, batch].concat();
            let result = owner::seal(authorization, SEALED_OUTPUTS_INFO, &aad, outputs.as_bytes())?;
            Ok((result, digest))
        }
        ServiceOperation::Claim { authorization } => {
            let (seed, digest) = unseal()?;
            let signer = owner::authorized(authorization, |signer| {
                claim_message(signer, network, &authorization.wallet_viewing_public_key)
            })?;
            let keys = keys::derive(&seed, &signer);
            let secrets = Zeroizing::new(
                [
                    keys.viewing.secret_bytes().as_slice(),
                    keys.nullifier.secret().as_slice(),
                ]
                .concat(),
            );
            let result = owner::seal(authorization, SEALED_KEYS_INFO, &signer, &secrets)?;
            Ok((result, digest))
        }
    }
}
