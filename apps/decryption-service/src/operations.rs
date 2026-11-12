//! The encrypted operation endpoint.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use spr_tvc_enclave::{http, open_ciphertexts, open_envelope, respond, Failure, Service};
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::parse_uncompressed_sec1;
use zolana_tvc_protocol::decryption_service::{
    parse_service_request, service_request_digest, DecryptedOutputs, ServiceOperation,
    ServiceRequest, ServiceResult, SERVICE_PROOF_TYPE,
};
use zolana_tvc_protocol::types::{OperationKind, OperationProofPayload};

use crate::{keys, owner, seed};

/// Every operation this application serves.
pub const OPERATIONS: [OperationKind; 3] = [
    OperationKind::ServiceGenesis,
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
    let (result, sealed_seed_digest) = run(&request, &request_digest, service)?;
    let proof = OperationProofPayload {
        r#type: SERVICE_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: request.request_id,
        request_digest,
        result_digest: [0; 32],
        operation: request.operation.kind(),
        sealed_seed_digest,
    };
    respond(
        &service.ephemeral,
        proof,
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

/// Returns the result and the digest of the sealed master seed it came from.
fn run(
    request: &ServiceRequest,
    request_digest: &[u8; 32],
    service: &Service,
) -> Result<(ServiceResult, [u8; 32]), Failure> {
    let presented = request.sealed_master_seed.as_deref();
    let unseal = || seed::unseal(presented.ok_or(Failure::Invalid)?, service);
    match &request.operation {
        ServiceOperation::Genesis => {
            if presented.is_some() {
                return Err(Failure::Invalid);
            }
            let (sealed_master_seed, digest) = seed::generate(service)?;
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
            signer,
            signature,
            items,
        } => {
            let (seed, digest) = unseal()?;
            let signer =
                owner::authorized(signer, signature, service.info.network, request_digest)?;
            let keys = keys::derive(&seed, &signer);
            let outputs = DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts: open_ciphertexts(&keys.viewing, items)?,
            };
            Ok((ServiceResult::Decrypt(outputs), digest))
        }
    }
}

#[cfg(test)]
mod tests;
