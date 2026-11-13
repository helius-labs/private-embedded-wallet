//! What tests of an application here share: a release, and a client's half of the envelope.

use axum::body::Body;
use axum::http::Response;
use http_body_util::BodyExt as _;
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::{qos_decrypt, qos_encrypt, verify_p256_message, QosP256Public};
use zolana_tvc_protocol::digest::result_digest;
use zolana_tvc_protocol::encoding::parse_strict_json;
use zolana_tvc_protocol::types::{
    EncryptedRequest, EncryptedResponse, OperationProofPayload, ServiceInfo, WalletGrant,
};

use crate::Release;

pub fn release() -> Release {
    Release {
        security_domain_id: [0x11; 32],
        release_id: "release-test".to_owned(),
        quorum_key_id: "quorum-test".to_owned(),
        quorum_key_epoch: 1,
    }
}

/// `plaintext` encrypted to the running Quorum key, as a client sends it.
pub fn encrypt_request(
    info: &ServiceInfo,
    plaintext: &str,
    wallet_grant: Option<WalletGrant>,
) -> EncryptedRequest {
    let quorum = QosP256Public::from_bytes(&info.quorum_public_key).expect("quorum key");
    EncryptedRequest {
        version: API_VERSION,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        ciphertext: qos_encrypt(&quorum.encryption, plaintext.as_bytes()).expect("encrypt"),
        wallet_grant,
    }
}

/// Opens an answer as a client does: checks the App Proof, then decrypts.
pub fn open_response(
    info: &ServiceInfo,
    response: &str,
    response_secret: &[u8; 32],
) -> (OperationProofPayload, Zeroizing<Vec<u8>>) {
    let response: EncryptedResponse = parse_strict_json(response).expect("response");
    let proof = response.tvc_app_proof;
    assert_eq!(proof.public_key, info.ephemeral_public_key);
    let ephemeral = QosP256Public::from_bytes(&proof.public_key).expect("ephemeral key");
    verify_p256_message(
        &ephemeral.signing,
        proof.proof_payload.as_bytes(),
        &proof.signature,
    )
    .expect("app proof signature");
    let payload: OperationProofPayload =
        parse_strict_json(&proof.proof_payload).expect("proof payload");
    assert_eq!(payload.request_id, response.request_id);
    assert_eq!(
        payload.result_digest,
        result_digest(&response.encrypted_result)
    );
    let plaintext = qos_decrypt(response_secret, &response.encrypted_result).expect("result");
    (payload, plaintext)
}

pub async fn body(response: Response<Body>) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8")
}
