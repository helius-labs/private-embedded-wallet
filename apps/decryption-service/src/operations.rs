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

use crate::{keys, owner};

/// Every operation this application serves.
pub(crate) const OPERATIONS: [OperationKind; 2] = [
    OperationKind::ServicePublicKeys,
    OperationKind::ServiceDecrypt,
];

pub(crate) fn handle(service: &Service, body: &[u8]) -> Response<Body> {
    match execute(service, body) {
        Ok(response) => http::ok(response),
        Err(failure) => failure.into_response(),
    }
}

fn execute(service: &Service, body: &[u8]) -> Result<String, Failure> {
    let (grant, plaintext) = open_envelope(&service.info, &service.quorum, body)?;
    let request = parse_service_request(&plaintext).map_err(|_| Failure::Invalid)?;
    if grant.is_some() || !targets_running_release(&request, service) {
        return Err(Failure::Invalid);
    }
    parse_uncompressed_sec1(&request.client_response_public_key).map_err(|_| Failure::Invalid)?;

    let request_digest = service_request_digest(&request).map_err(|_| Failure::Invalid)?;
    let result = run(&request, &request_digest, service)?;
    let binding = ProofBinding {
        proof_type: SERVICE_PROOF_TYPE,
        request_id: request.request_id,
        request_digest,
        operation: request.operation.kind(),
        // The Quorum key names the seed; there is no sealed one.
        sealed_seed_digest: [0; 32],
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

fn run(
    request: &ServiceRequest,
    request_digest: &[u8; 32],
    service: &Service,
) -> Result<ServiceResult, Failure> {
    let seed = keys::master_seed(&service.quorum);
    match &request.operation {
        ServiceOperation::PublicKeys { address } => {
            let keys = keys::derive(&seed, &owner::address_key(address)?.to_bytes());
            Ok(ServiceResult::PublicKeys {
                viewing_public_key: *keys.viewing.pubkey().as_bytes(),
                nullifier_public_key: keys.nullifier.pubkey().map_err(|_| Failure::Unavailable)?,
            })
        }
        ServiceOperation::Decrypt {
            signer,
            signature,
            items,
        } => {
            let signer =
                owner::authorized(signer, signature, service.info.network, request_digest)?;
            let keys = keys::derive(&seed, &signer);
            // No item: the owner asks for the nullifier secret alone.
            let plaintexts = if items.is_empty() {
                Vec::new()
            } else {
                open_ciphertexts(&keys.viewing, items)?
            };
            Ok(ServiceResult::Decrypt(DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts,
            }))
        }
    }
}

#[cfg(test)]
mod tests;
