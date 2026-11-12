use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer as _, SigningKey};
use qos_p256::P256Pair;
use solana_pubkey::Pubkey;
use spr_keypair::viewing_key::random_salt;
use spr_keypair::{NullifierKey, ViewingKey, X25519Pubkey};
use spr_tvc_enclave::{testing, NETWORK};
use tower::ServiceExt as _;
use zeroize::Zeroizing;
use zolana_tvc_protocol::crypto::public_key_uncompressed;
use zolana_tvc_protocol::decryption_service::decrypt_message;
use zolana_tvc_protocol::digest::sealed_seed_digest;
use zolana_tvc_protocol::encoding::{jcs_serialize, parse_strict_json};
use zolana_tvc_protocol::types::{
    DecryptItem, DecryptLabel, EncryptedRequest, Network, ServiceInfo, WalletGrant,
};

use super::*;
use crate::{router, APP};

const RESPONSE_SECRET: [u8; 32] = [0x42; 32];

fn other(network: Network) -> Network {
    match network {
        Network::Devnet => Network::Mainnet,
        Network::Mainnet => Network::Devnet,
    }
}

fn service_on(network: Network, quorum_seed: u8) -> Service {
    let quorum = P256Pair::from_master_seed(&Zeroizing::new([quorum_seed; 32])).unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let mut info =
        testing::release().service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
    info.network = network;
    Service::new(info, ephemeral, quorum)
}

fn service() -> Service {
    service_on(NETWORK, 1)
}

fn request(
    service: &Service,
    sealed_master_seed: Option<Vec<u8>>,
    operation: ServiceOperation,
) -> ServiceRequest {
    let response_secret = p256::SecretKey::from_slice(&RESPONSE_SECRET).unwrap();
    let info = &service.info;
    ServiceRequest {
        version: API_VERSION,
        request_id: [0x77; 32],
        target_release_id: info.release_id.clone(),
        target_manifest_digest: info.manifest_digest,
        target_executable_digest: info.executable_digest,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        sealed_master_seed,
        client_response_public_key: public_key_uncompressed(&response_secret.public_key()).to_vec(),
        operation,
    }
}

fn envelope(service: &Service, request: &ServiceRequest) -> EncryptedRequest {
    testing::encrypt_request(&service.info, &jcs_serialize(request).unwrap(), None)
}

/// Opens an answer as a client does. Returns the result and the sealed-seed digest the proof names.
fn open(service: &Service, request: &ServiceRequest, response: &str) -> (ServiceResult, [u8; 32]) {
    let (payload, plaintext) = testing::open_response(&service.info, response, &RESPONSE_SECRET);
    assert_eq!(payload.r#type, SERVICE_PROOF_TYPE);
    assert_eq!(payload.request_id, request.request_id);
    assert_eq!(
        payload.request_digest,
        service_request_digest(request).unwrap()
    );
    assert_eq!(payload.operation, request.operation.kind());
    (
        parse_strict_json(std::str::from_utf8(&plaintext).unwrap()).unwrap(),
        payload.sealed_seed_digest,
    )
}

fn call(service: &Service, request: &ServiceRequest) -> Result<ServiceResult, Failure> {
    let body = jcs_serialize(&envelope(service, request)).unwrap();
    let response = execute(service, body.as_bytes())?;
    let (result, digest) = open(service, request, &response);
    if let Some(sealed) = &request.sealed_master_seed {
        assert_eq!(digest, sealed_seed_digest(sealed));
    }
    Ok(result)
}

fn refused(service: &Service, request: &ServiceRequest) {
    assert_eq!(call(service, request).unwrap_err(), Failure::Invalid);
}

fn genesis(service: &Service) -> Vec<u8> {
    let request = request(service, None, ServiceOperation::Genesis);
    let ServiceResult::Genesis { sealed_master_seed } = call(service, &request).unwrap() else {
        panic!("expected a Genesis result");
    };
    sealed_master_seed
}

fn public_keys(service: &Service, seed: &[u8], owner: &SigningKey) -> ServiceRequest {
    request(
        service,
        Some(seed.to_vec()),
        ServiceOperation::PublicKeys {
            address: base58(owner),
        },
    )
}

fn base58(owner: &SigningKey) -> String {
    Pubkey::new_from_array(owner.verifying_key().to_bytes()).to_string()
}

/// The service viewing and nullifier public keys of `owner`.
fn service_keys(service: &Service, seed: &[u8], owner: &SigningKey) -> ([u8; 33], [u8; 32]) {
    let ServiceResult::PublicKeys {
        viewing_public_key,
        nullifier_public_key,
    } = call(service, &public_keys(service, seed, owner)).unwrap()
    else {
        panic!("expected a PublicKeys result");
    };
    (viewing_public_key, nullifier_public_key)
}

/// A `Decrypt` request for `items` that `owner` signed for `network`.
fn decrypt(
    service: &Service,
    seed: &[u8],
    owner: &SigningKey,
    network: Network,
    items: Vec<DecryptItem>,
) -> ServiceRequest {
    let mut request = request(
        service,
        Some(seed.to_vec()),
        ServiceOperation::Decrypt {
            signer: base58(owner),
            signature: [0; 64],
            items,
        },
    );
    let message = decrypt_message(
        &owner.verifying_key().to_bytes(),
        network,
        &service_request_digest(&request).unwrap(),
    );
    let ServiceOperation::Decrypt { signature, .. } = &mut request.operation else {
        unreachable!()
    };
    *signature = owner.sign(&message).to_bytes();
    request
}

/// `plaintext` as a sender encrypts it to `viewing_public_key` in one slot.
fn sent(viewing_public_key: [u8; 33], named: [u8; 33], plaintext: &[u8], slot: u32) -> DecryptItem {
    let transaction = ViewingKey::new();
    let salt = random_salt();
    DecryptItem {
        ciphertext: transaction
            .encrypt_slot(
                &X25519Pubkey::from_bytes(viewing_public_key).unwrap(),
                plaintext,
                salt,
                slot,
            )
            .unwrap(),
        viewing_public_key: named.to_vec(),
        transaction_viewing_public_key: transaction.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: slot.into(),
        label: DecryptLabel::Transfer,
    }
}

#[test]
fn the_owner_decrypts_what_a_sender_encrypted_to_the_service_keys() {
    let service = service();
    let seed = genesis(&service);
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, nullifier) = service_keys(&service, &seed, &owner);
    let (stranger, _) = service_keys(&service, &seed, &SigningKey::from_bytes(&[9; 32]));
    assert_ne!(viewing, stranger);

    // The second output is for another key, as a dummy under the owner's tag is.
    let items = vec![
        sent(viewing, viewing, b"ten usdc", 3),
        sent(stranger, viewing, b"not ours", 4),
    ];
    let request = decrypt(&service, &seed, &owner, NETWORK, items);
    let ServiceResult::Decrypt(outputs) = call(&service, &request).unwrap() else {
        panic!("expected a Decrypt result");
    };

    assert_eq!(outputs.plaintexts[0], b"ten usdc");
    assert_eq!(outputs.plaintexts[1].len(), b"not ours".len());
    assert_ne!(outputs.plaintexts[1], b"not ours");
    assert_eq!(
        NullifierKey::from_secret(outputs.nullifier_secret)
            .pubkey()
            .unwrap(),
        nullifier
    );
}

#[test]
fn a_decrypt_needs_the_owner_signature_over_this_request_and_network() {
    let service = service();
    let seed = genesis(&service);
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&service, &seed, &owner);
    let items = vec![sent(viewing, viewing, b"ten usdc", 0)];
    let valid = decrypt(&service, &seed, &owner, NETWORK, items.clone());
    assert!(call(&service, &valid).is_ok());

    refused(
        &service,
        &decrypt(&service, &seed, &owner, other(NETWORK), items),
    );

    // The signature is for one request: its signer, items, response key and id.
    let edits: [fn(&mut ServiceRequest); 5] = [
        |r| {
            let ServiceOperation::Decrypt { signer, .. } = &mut r.operation else {
                unreachable!()
            };
            *signer = base58(&SigningKey::from_bytes(&[9; 32]));
        },
        |r| {
            let ServiceOperation::Decrypt { signature, .. } = &mut r.operation else {
                unreachable!()
            };
            signature[0] ^= 1;
        },
        |r| {
            let ServiceOperation::Decrypt { items, .. } = &mut r.operation else {
                unreachable!()
            };
            items[0].slot_index = 1;
        },
        |r| {
            let another = p256::SecretKey::from_slice(&[0x43; 32]).unwrap();
            r.client_response_public_key = public_key_uncompressed(&another.public_key()).to_vec();
        },
        |r| r.request_id[0] ^= 1,
    ];
    for edit in edits {
        let mut request = valid.clone();
        edit(&mut request);
        let body = jcs_serialize(&envelope(&service, &request)).unwrap();
        assert_eq!(
            execute(&service, body.as_bytes()).unwrap_err(),
            Failure::Invalid
        );
    }
}

#[test]
fn a_batch_holds_items_under_the_signers_service_viewing_key() {
    let service = service();
    let seed = genesis(&service);
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&service, &seed, &owner);
    let (stranger, _) = service_keys(&service, &seed, &SigningKey::from_bytes(&[9; 32]));
    for items in [Vec::new(), vec![sent(viewing, stranger, b"ten usdc", 0)]] {
        refused(&service, &decrypt(&service, &seed, &owner, NETWORK, items));
    }
}

#[test]
fn only_an_address_a_key_can_sign_for_has_service_keys() {
    let service = service();
    let seed = genesis(&service);
    let off_curve = (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("an off-curve address");
    // The identity point, of order one.
    let mut small_order = [0u8; 32];
    small_order[0] = 1;
    for address in [
        Pubkey::new_from_array(off_curve).to_string(),
        Pubkey::new_from_array(small_order).to_string(),
        "not base58!".to_owned(),
    ] {
        refused(
            &service,
            &request(
                &service,
                Some(seed.clone()),
                ServiceOperation::PublicKeys { address },
            ),
        );
    }
}

#[test]
fn a_sealed_seed_is_one_this_enclave_drew_for_its_quorum_key_and_network() {
    let service = service();
    let seed = genesis(&service);
    assert_ne!(seed, genesis(&service), "every Genesis draws another seed");
    let owner = SigningKey::from_bytes(&[5; 32]);
    let with = |service: &Service, sealed: Option<Vec<u8>>| {
        let mut request = public_keys(service, &seed, &owner);
        request.sealed_master_seed = sealed;
        request
    };

    let mut tampered = seed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    refused(&service, &with(&service, None));
    refused(&service, &with(&service, Some(tampered)));
    // Anyone can encrypt a seed they know to the Quorum key; only the enclave signs one.
    refused(
        &service,
        &with(&service, Some(seed::forged(&service, [9; 32]))),
    );
    refused(
        &service,
        &request(&service, Some(seed.clone()), ServiceOperation::Genesis),
    );
    for elsewhere in [service_on(NETWORK, 2), service_on(other(NETWORK), 1)] {
        refused(&elsewhere, &with(&elsewhere, Some(seed.clone())));
    }
}

#[test]
fn a_request_is_bound_to_the_running_release() {
    let service = service();
    let seed = genesis(&service);
    let base = public_keys(&service, &seed, &SigningKey::from_bytes(&[5; 32]));
    assert!(call(&service, &base).is_ok());

    let edits: [fn(&mut ServiceRequest); 7] = [
        |r| r.version = 2,
        |r| r.target_release_id.push('x'),
        |r| r.target_manifest_digest[0] ^= 1,
        |r| r.target_executable_digest[0] ^= 1,
        |r| r.quorum_key_id.push('x'),
        |r| r.quorum_key_epoch = 2,
        |r| r.client_response_public_key = vec![0; 65],
    ];
    for edit in edits {
        let mut request = base.clone();
        edit(&mut request);
        refused(&service, &request);
    }

    let mut with_grant = envelope(&service, &base);
    with_grant.wallet_grant = Some(WalletGrant {
        version: API_VERSION,
        descriptor_digest: [0; 32],
        client_key_id: String::new(),
        project_id: String::new(),
        issued_at_ms: 0,
        expires_at_ms: 0,
        signature: Vec::new(),
    });
    for body in [jcs_serialize(&with_grant).unwrap(), "{}".to_owned()] {
        assert_eq!(
            execute(&service, body.as_bytes()).unwrap_err(),
            Failure::Invalid
        );
    }
}

#[tokio::test]
async fn the_router_advertises_the_operations_and_serves_them() {
    let service = service();
    let response = router(service.clone())
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let info: ServiceInfo = parse_strict_json(&testing::body(response).await).unwrap();
    assert_eq!(info.supported_operations, OPERATIONS);
    assert_eq!(info.proof_type, SERVICE_PROOF_TYPE);

    let request = request(&service, None, ServiceOperation::Genesis);
    let body = jcs_serialize(&envelope(&service, &request)).unwrap();
    let response = router(service.clone())
        .oneshot(
            Request::post("/v1/operations")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (result, _) = open(&service, &request, &testing::body(response).await);
    assert!(matches!(result, ServiceResult::Genesis { .. }));
}
