//! The encrypted operation endpoint.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use spr_tvc_enclave::{
    http, open_ciphertexts, open_envelope, respond, Failure, ProofBinding, Service,
};
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::parse_uncompressed_sec1;
use zolana_tvc_protocol::decryption_service::{
    parse_service_request, service_request_digest, DecryptedOutputs, ServiceOperation,
    ServiceRequest, ServiceResult, SERVICE_PROOF_TYPE,
};
use zolana_tvc_protocol::types::OperationKind;

use crate::{backup, keys, owner, seed, State};

/// Every operation this application serves.
pub(crate) const OPERATIONS: [OperationKind; 5] = [
    OperationKind::ServiceGenesis,
    OperationKind::ServicePublicKeys,
    OperationKind::ServiceDecrypt,
    OperationKind::ServiceBackup,
    OperationKind::ServiceRestore,
];

pub(crate) fn handle(state: &State, body: &[u8]) -> Response<Body> {
    match execute(state, body) {
        Ok(response) => http::ok(response),
        Err(failure) => failure.into_response(),
    }
}

fn execute(state: &State, body: &[u8]) -> Result<String, Failure> {
    let service = &state.service;
    let (grant, plaintext) = open_envelope(&service.info, &service.quorum, body)?;
    let request = parse_service_request(&plaintext).map_err(|_| Failure::Invalid)?;
    if grant.is_some() || !targets_running_release(&request, service) {
        return Err(Failure::Invalid);
    }
    parse_uncompressed_sec1(&request.client_response_public_key).map_err(|_| Failure::Invalid)?;

    let request_digest = service_request_digest(&request).map_err(|_| Failure::Invalid)?;
    let (result, seed_commitment) = run(&request, &request_digest, state)?;
    let binding = ProofBinding {
        proof_type: SERVICE_PROOF_TYPE,
        request_id: request.request_id,
        request_digest,
        operation: request.operation.kind(),
        sealed_seed_digest: seed_commitment,
    };
    respond(
        &service.ephemeral,
        binding,
        &request.client_response_public_key,
        &result,
    )
}

fn targets_running_release(request: &ServiceRequest, service: &Service) -> bool {
    let info = &service.info;
    request.version == API_VERSION
        && request.target_release_id == info.release_id
        && request.target_manifest_digest == info.manifest_digest
        && request.target_executable_digest == info.executable_digest
        && request.quorum_key_id == info.quorum_key_id
        && request.quorum_key_epoch == info.quorum_key_epoch
}

/// Returns the result and the commitment of the seed it came from.
fn run(
    request: &ServiceRequest,
    request_digest: &[u8; 32],
    state: &State,
) -> Result<(ServiceResult, [u8; 32]), Failure> {
    let service = &state.service;
    let pinned = state.custody.seed_commitment;
    let presented = request.sealed_master_seed.as_deref();
    let seed = match (&request.operation, presented) {
        (ServiceOperation::Genesis | ServiceOperation::Restore { .. }, Some(_)) => {
            return Err(Failure::Invalid)
        }
        (ServiceOperation::Genesis, None) if pinned.is_none() => seed::draw(),
        (ServiceOperation::Restore { shares }, None) => backup::rebuild(shares, service)?,
        (_, Some(blob)) => seed::unseal(blob, service)?,
        _ => return Err(Failure::Invalid),
    };
    let commitment = keys::commitment(&seed);
    let serves_keys = matches!(
        request.operation,
        ServiceOperation::PublicKeys { .. } | ServiceOperation::Decrypt { .. }
    );
    match pinned {
        Some(pinned) if pinned != commitment => return Err(Failure::Invalid),
        None if serves_keys => return Err(Failure::Invalid),
        _ => {}
    }

    let result = match &request.operation {
        ServiceOperation::Genesis | ServiceOperation::Restore { .. } => ServiceResult::MasterSeed {
            sealed_master_seed: seed::seal_here(service, &seed)?,
        },
        ServiceOperation::Backup => backup::split(&seed, &state.custody)?,
        ServiceOperation::PublicKeys { address } => {
            let keys = keys::derive(&seed, &owner::address_key(address)?.to_bytes());
            ServiceResult::PublicKeys {
                viewing_public_key: *keys.viewing.pubkey().as_bytes(),
                nullifier_public_key: keys.nullifier.pubkey().map_err(|_| Failure::Unavailable)?,
            }
        }
        ServiceOperation::Decrypt {
            signer,
            signature,
            items,
        } => {
            let signer =
                owner::authorized(signer, signature, service.info.network, request_digest)?;
            let keys = keys::derive(&seed, &signer);
            ServiceResult::Decrypt(DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts: open_ciphertexts(&keys.viewing, items)?,
            })
        }
    };
    Ok((result, commitment))
}

#[cfg(test)]
mod tests;
