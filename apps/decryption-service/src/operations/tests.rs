use std::sync::Arc;

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
use zolana_tvc_protocol::crypto::{
    public_key_uncompressed, qos_decrypt, qos_encrypt, QosP256Public,
};
use zolana_tvc_protocol::decryption_service::{decrypt_message, HolderShare};
use zolana_tvc_protocol::encoding::{jcs_serialize, parse_strict_json};
use zolana_tvc_protocol::types::{
    DecryptItem, DecryptLabel, EncryptedRequest, Network, ServiceInfo, WalletGrant,
};

use super::*;
use crate::custody::Custody;
use crate::{router, State, APP};

const RESPONSE_SECRET: [u8; 32] = [0x42; 32];

fn other(network: Network) -> Network {
    match network {
        Network::Devnet => Network::Mainnet,
        Network::Mainnet => Network::Devnet,
    }
}

fn holder_secret(index: u8) -> [u8; 32] {
    [0x61 + index; 32]
}

fn holder_key(index: u8) -> Vec<u8> {
    let secret = p256::SecretKey::from_slice(&holder_secret(index)).unwrap();
    public_key_uncompressed(&secret.public_key()).to_vec()
}

/// Custody with holders `0..holders` and `threshold`, serving the seed `pinned`.
fn custody(pinned: Option<[u8; 32]>, holders: u8, threshold: u8) -> Custody {
    Custody {
        seed_commitment: pinned,
        backup_holders: (0..holders).map(holder_key).collect(),
        backup_threshold: Some(threshold),
    }
}

fn state_on(network: Network, quorum_seed: u8, custody: Custody) -> State {
    let quorum = P256Pair::from_master_seed(&Zeroizing::new([quorum_seed; 32])).unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let mut info =
        testing::release().service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
    info.network = network;
    State {
        service: Service::new(info, ephemeral, quorum),
        custody: Arc::new(custody),
    }
}

/// A release that pins no seed, with a 2-of-3 backup.
fn bootstrap() -> State {
    state_on(NETWORK, 1, custody(None, 3, 2))
}

/// A release serving a seed its bootstrap release drew, and that seed sealed.
fn seeded() -> (State, Vec<u8>) {
    let (sealed, commitment) = genesis(&bootstrap());
    (
        state_on(NETWORK, 1, custody(Some(commitment), 3, 2)),
        sealed,
    )
}

fn request(
    state: &State,
    sealed_master_seed: Option<Vec<u8>>,
    operation: ServiceOperation,
) -> ServiceRequest {
    let response_secret = p256::SecretKey::from_slice(&RESPONSE_SECRET).unwrap();
    let info = &state.service.info;
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

fn envelope(state: &State, request: &ServiceRequest) -> EncryptedRequest {
    testing::encrypt_request(&state.service.info, &jcs_serialize(request).unwrap(), None)
}

/// Opens an answer as a client does. Returns the result and the seed commitment the proof names.
fn open(state: &State, request: &ServiceRequest, response: &str) -> (ServiceResult, [u8; 32]) {
    let (payload, plaintext) =
        testing::open_response(&state.service.info, response, &RESPONSE_SECRET);
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

fn call(state: &State, request: &ServiceRequest) -> Result<ServiceResult, Failure> {
    let body = jcs_serialize(&envelope(state, request)).unwrap();
    let response = execute(state, body.as_bytes())?;
    let (result, commitment) = open(state, request, &response);
    if let Some(pinned) = state.custody.seed_commitment {
        assert_eq!(commitment, pinned);
    }
    Ok(result)
}

fn refused(state: &State, request: &ServiceRequest) {
    assert_eq!(call(state, request).unwrap_err(), Failure::Invalid);
}

/// A seed `state` drew, sealed, and its commitment.
fn genesis(state: &State) -> (Vec<u8>, [u8; 32]) {
    let request = request(state, None, ServiceOperation::Genesis);
    let body = jcs_serialize(&envelope(state, &request)).unwrap();
    let response = execute(state, body.as_bytes()).unwrap();
    let (ServiceResult::MasterSeed { sealed_master_seed }, commitment) =
        open(state, &request, &response)
    else {
        panic!("expected a MasterSeed result");
    };
    (sealed_master_seed, commitment)
}

fn public_keys(state: &State, seed: &[u8], owner: &SigningKey) -> ServiceRequest {
    request(
        state,
        Some(seed.to_vec()),
        ServiceOperation::PublicKeys {
            address: base58(owner),
        },
    )
}

fn base58(owner: &SigningKey) -> String {
    Pubkey::new_from_array(owner.verifying_key().to_bytes()).to_string()
}

/// The state viewing and nullifier public keys of `owner`.
fn service_keys(state: &State, seed: &[u8], owner: &SigningKey) -> ([u8; 33], [u8; 32]) {
    let ServiceResult::PublicKeys {
        viewing_public_key,
        nullifier_public_key,
    } = call(state, &public_keys(state, seed, owner)).unwrap()
    else {
        panic!("expected a PublicKeys result");
    };
    (viewing_public_key, nullifier_public_key)
}

/// A `Decrypt` request for `items` that `owner` signed for `network`.
fn decrypt(
    state: &State,
    seed: &[u8],
    owner: &SigningKey,
    network: Network,
    items: Vec<DecryptItem>,
) -> ServiceRequest {
    let mut request = request(
        state,
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
    let (state, seed) = seeded();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, nullifier) = service_keys(&state, &seed, &owner);
    let (stranger, _) = service_keys(&state, &seed, &SigningKey::from_bytes(&[9; 32]));
    assert_ne!(viewing, stranger);

    // The second output is for another key, as a dummy under the owner's tag is.
    let items = vec![
        sent(viewing, viewing, b"ten usdc", 3),
        sent(stranger, viewing, b"not ours", 4),
    ];
    let request = decrypt(&state, &seed, &owner, NETWORK, items);
    let ServiceResult::Decrypt(outputs) = call(&state, &request).unwrap() else {
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
    let (state, seed) = seeded();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&state, &seed, &owner);
    let items = vec![sent(viewing, viewing, b"ten usdc", 0)];
    let valid = decrypt(&state, &seed, &owner, NETWORK, items.clone());
    assert!(call(&state, &valid).is_ok());

    refused(
        &state,
        &decrypt(&state, &seed, &owner, other(NETWORK), items),
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
        let body = jcs_serialize(&envelope(&state, &request)).unwrap();
        assert_eq!(
            execute(&state, body.as_bytes()).unwrap_err(),
            Failure::Invalid
        );
    }
}

#[test]
fn a_batch_holds_items_under_the_signers_service_viewing_key() {
    let (state, seed) = seeded();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&state, &seed, &owner);
    let (stranger, _) = service_keys(&state, &seed, &SigningKey::from_bytes(&[9; 32]));
    for items in [Vec::new(), vec![sent(viewing, stranger, b"ten usdc", 0)]] {
        refused(&state, &decrypt(&state, &seed, &owner, NETWORK, items));
    }
}

#[test]
fn only_an_address_a_key_can_sign_for_has_service_keys() {
    let (state, seed) = seeded();
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
            &state,
            &request(
                &state,
                Some(seed.clone()),
                ServiceOperation::PublicKeys { address },
            ),
        );
    }
}

#[test]
fn a_release_serves_only_its_pinned_seed() {
    let (state, seed) = seeded();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let with = |state: &State, sealed: Option<Vec<u8>>| {
        let mut request = public_keys(state, &seed, &owner);
        request.sealed_master_seed = sealed;
        request
    };
    assert!(call(&state, &with(&state, Some(seed.clone()))).is_ok());

    let (another, _) = genesis(&bootstrap());
    let mut tampered = seed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    refused(&state, &with(&state, None));
    refused(&state, &with(&state, Some(another)));
    refused(&state, &with(&state, Some(tampered)));
    // Anyone can encrypt a seed they know to the Quorum key; only the enclave signs one.
    refused(
        &state,
        &with(&state, Some(seed::forged(&state.service, [9; 32]))),
    );
    refused(&state, &request(&state, None, ServiceOperation::Genesis));
    let pinned = state.custody.seed_commitment;
    for elsewhere in [
        state_on(NETWORK, 2, custody(pinned, 3, 2)),
        state_on(other(NETWORK), 1, custody(pinned, 3, 2)),
    ] {
        refused(&elsewhere, &with(&elsewhere, Some(seed.clone())));
    }
}

#[test]
fn a_release_without_a_pinned_seed_only_draws_and_backs_up() {
    let state = bootstrap();
    let (seed, _) = genesis(&state);
    let (another, _) = genesis(&state);
    assert_ne!(seed, another, "every Genesis draws another seed");
    let owner = SigningKey::from_bytes(&[5; 32]);
    refused(&state, &public_keys(&state, &seed, &owner));
    refused(&state, &decrypt(&state, &seed, &owner, NETWORK, Vec::new()));
    assert_eq!(backup(&state, &seed).len(), 3);
}

/// What `state` gives each holder for `seed`.
fn backup(state: &State, seed: &[u8]) -> Vec<HolderShare> {
    let request = request(state, Some(seed.to_vec()), ServiceOperation::Backup);
    let ServiceResult::Backup { shares, .. } = call(state, &request).unwrap() else {
        panic!("expected a Backup result");
    };
    shares
}

/// Holder `index` opens its share and encrypts it to `state`'s Quorum key.
fn hand_over(share: &HolderShare, index: u8, state: &State) -> Vec<u8> {
    assert_eq!(share.holder_public_key, holder_key(index));
    let plaintext = qos_decrypt(&holder_secret(index), &share.ciphertext).unwrap();
    let quorum = QosP256Public::from_bytes(&state.service.info.quorum_public_key).unwrap();
    qos_encrypt(&quorum.encryption, &plaintext).unwrap()
}

fn restore(state: &State, shares: Vec<Vec<u8>>) -> Result<Vec<u8>, Failure> {
    let request = request(state, None, ServiceOperation::Restore { shares });
    let ServiceResult::MasterSeed { sealed_master_seed } = call(state, &request)? else {
        panic!("expected a MasterSeed result");
    };
    Ok(sealed_master_seed)
}

#[test]
fn the_seed_survives_a_new_quorum_key_through_its_backup() {
    let (state, seed) = seeded();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let keys = service_keys(&state, &seed, &owner);
    let shares = backup(&state, &seed);

    // Another Quorum key, as after a rotation or in another account.
    let moved = state_on(NETWORK, 2, custody(state.custody.seed_commitment, 3, 2));
    refused(&moved, &public_keys(&moved, &seed, &owner));
    let two = |a: u8, b: u8, set: &[HolderShare], to: &State| {
        vec![
            hand_over(&set[usize::from(a)], a, to),
            hand_over(&set[usize::from(b)], b, to),
        ]
    };
    let resealed = restore(&moved, two(0, 2, &shares, &moved)).unwrap();
    assert_eq!(service_keys(&moved, &resealed, &owner), keys);

    // One share is below the threshold.
    let one = vec![hand_over(&shares[1], 1, &moved)];
    assert_eq!(restore(&moved, one).unwrap_err(), Failure::Invalid);
    // Shares of two backups do not combine into the pinned seed.
    let second = backup(&state, &seed);
    let mixed = vec![
        hand_over(&shares[0], 0, &moved),
        hand_over(&second[1], 1, &moved),
    ];
    assert_eq!(restore(&moved, mixed).unwrap_err(), Failure::Invalid);
    // A release pinned to another seed refuses this one.
    let (_, other_commitment) = genesis(&bootstrap());
    let elsewhere = state_on(NETWORK, 2, custody(Some(other_commitment), 3, 2));
    let shares_there = two(0, 1, &shares, &elsewhere);
    assert_eq!(
        restore(&elsewhere, shares_there).unwrap_err(),
        Failure::Invalid
    );
}

#[test]
fn old_shares_restore_under_a_larger_holder_set() {
    let (state, seed) = seeded();
    let shares = backup(&state, &seed);
    let larger = state_on(NETWORK, 2, custody(state.custody.seed_commitment, 5, 3));
    let old = vec![
        hand_over(&shares[1], 1, &larger),
        hand_over(&shares[2], 2, &larger),
    ];
    let resealed = restore(&larger, old).unwrap();
    assert_eq!(backup(&larger, &resealed).len(), 5);
}

#[test]
fn a_backup_needs_holders() {
    let (state, seed) = seeded();
    let without = state_on(
        NETWORK,
        1,
        Custody {
            seed_commitment: state.custody.seed_commitment,
            ..Custody::default()
        },
    );
    refused(
        &without,
        &request(&without, Some(seed), ServiceOperation::Backup),
    );
}

#[test]
fn custody_needs_a_threshold_from_two_to_the_holder_count() {
    assert!(Custody::default().check().is_ok());
    assert!(custody(None, 3, 2).check().is_ok());
    assert!(custody(None, 3, 3).check().is_ok());
    for (holders, threshold) in [(3, 1), (3, 4), (0, 2)] {
        assert!(custody(None, holders, threshold).check().is_err());
    }
    let mut no_threshold = custody(None, 3, 2);
    no_threshold.backup_threshold = None;
    assert!(no_threshold.check().is_err());
}

#[test]
fn a_request_is_bound_to_the_running_release() {
    let (state, seed) = seeded();
    let base = public_keys(&state, &seed, &SigningKey::from_bytes(&[5; 32]));
    assert!(call(&state, &base).is_ok());

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
        refused(&state, &request);
    }

    let mut with_grant = envelope(&state, &base);
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
            execute(&state, body.as_bytes()).unwrap_err(),
            Failure::Invalid
        );
    }
}

#[tokio::test]
async fn the_router_advertises_the_operations_and_serves_them() {
    let state = bootstrap();
    let response = router(state.clone())
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let info: ServiceInfo = parse_strict_json(&testing::body(response).await).unwrap();
    assert_eq!(info.supported_operations, OPERATIONS);
    assert_eq!(info.proof_type, SERVICE_PROOF_TYPE);

    let request = request(&state, None, ServiceOperation::Genesis);
    let body = jcs_serialize(&envelope(&state, &request)).unwrap();
    let response = router(state.clone())
        .oneshot(
            Request::post("/v1/operations")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (result, _) = open(&state, &request, &testing::body(response).await);
    assert!(matches!(result, ServiceResult::MasterSeed { .. }));
}
