use std::sync::Arc;

use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer as _, SigningKey};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR};
use http_body_util::BodyExt as _;
use qos_p256::P256Pair;
use solana_pubkey::Pubkey;
use spr_keypair::viewing_key::random_salt;
use spr_keypair::{NullifierKey, ViewingKey, X25519Pubkey};
use spr_tvc_enclave::{Release, NETWORK};
use tower::ServiceExt as _;
use zolana_tvc_protocol::crypto::{
    public_key_uncompressed, qos_decrypt, qos_encrypt, verify_p256_message, QosP256Public,
};
use zolana_tvc_protocol::decryption_service::{OwnerAuthorization, SEALED_OUTPUTS_INFO};
use zolana_tvc_protocol::digest::{result_digest, sealed_seed_digest};
use zolana_tvc_protocol::encoding::parse_strict_json;
use zolana_tvc_protocol::types::{
    DecryptItem, DecryptLabel, EncryptedRequest, EncryptedResponse, Network, ServiceInfo,
    WalletGrant,
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
    let release = Release {
        security_domain_id: [0x11; 32],
        release_id: "service-test".to_owned(),
        quorum_key_id: "quorum-test".to_owned(),
        quorum_key_epoch: 1,
    };
    let mut info = release.service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
    info.network = network;
    Service {
        info: Arc::new(info),
        ephemeral: Arc::new(ephemeral),
        quorum: Arc::new(quorum),
    }
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
    let quorum = QosP256Public::from_bytes(&service.info.quorum_public_key).unwrap();
    EncryptedRequest {
        version: API_VERSION,
        quorum_key_id: service.info.quorum_key_id.clone(),
        quorum_key_epoch: service.info.quorum_key_epoch,
        ciphertext: qos_encrypt(
            &quorum.encryption,
            jcs_serialize(request).unwrap().as_bytes(),
        )
        .unwrap(),
        wallet_grant: None,
    }
}

/// Opens an answer as a client does: checks the App Proof, then decrypts.
/// Returns the result and the sealed-seed digest the proof names.
fn open(service: &Service, request: &ServiceRequest, response: &str) -> (ServiceResult, [u8; 32]) {
    let response: EncryptedResponse = parse_strict_json(response).unwrap();
    assert_eq!(response.request_id, request.request_id);
    let proof = response.tvc_app_proof;
    assert_eq!(proof.public_key, service.info.ephemeral_public_key);
    let ephemeral = QosP256Public::from_bytes(&proof.public_key).unwrap();
    verify_p256_message(
        &ephemeral.signing,
        proof.proof_payload.as_bytes(),
        &proof.signature,
    )
    .unwrap();
    let payload: OperationProofPayload = parse_strict_json(&proof.proof_payload).unwrap();
    assert_eq!(payload.r#type, SERVICE_PROOF_TYPE);
    assert_eq!(
        payload.request_digest,
        service_request_digest(request).unwrap()
    );
    assert_eq!(
        payload.result_digest,
        result_digest(&response.encrypted_result)
    );
    assert_eq!(payload.operation, request.operation.kind());
    let plaintext = qos_decrypt(&RESPONSE_SECRET, &response.encrypted_result).unwrap();
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

fn refused(service: &Service, sealed: Option<&[u8]>, operation: ServiceOperation) {
    let request = request(service, sealed.map(<[u8]>::to_vec), operation);
    assert_eq!(call(service, &request).unwrap_err(), Failure::Invalid);
}

fn genesis(service: &Service) -> Vec<u8> {
    let request = request(service, None, ServiceOperation::Genesis);
    let ServiceResult::Genesis { sealed_master_seed } = call(service, &request).unwrap() else {
        panic!("expected a Genesis result");
    };
    sealed_master_seed
}

/// The owner of an address and the viewing key of the owner's own wallet.
struct Owner {
    key: SigningKey,
    wallet: ViewingKey,
}

impl Owner {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            wallet: ViewingKey::from_bytes(&[seed.wrapping_add(1); 32]),
        }
    }

    fn address(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn base58(&self) -> String {
        Pubkey::new_from_array(self.address()).to_string()
    }

    fn public_keys(&self, service: &Service, seed: &[u8]) -> ([u8; 33], [u8; 32]) {
        let request = request(
            service,
            Some(seed.to_vec()),
            ServiceOperation::PublicKeys {
                address: self.base58(),
            },
        );
        let ServiceResult::PublicKeys {
            viewing_public_key,
            nullifier_public_key,
        } = call(service, &request).unwrap()
        else {
            panic!("expected a PublicKeys result");
        };
        (viewing_public_key, nullifier_public_key)
    }

    /// Signs for `items` to be opened for `wallet` on `network`.
    fn authorization(
        &self,
        network: Network,
        wallet: [u8; 33],
        items: &[DecryptItem],
    ) -> OwnerAuthorization {
        let batch = decrypt_items_digest(items).unwrap();
        OwnerAuthorization {
            signer: self.base58(),
            wallet_viewing_public_key: wallet,
            signature: self
                .key
                .sign(&decrypt_message(&self.address(), network, &wallet, &batch))
                .to_bytes(),
        }
    }

    fn decrypt(&self, items: &[DecryptItem]) -> ServiceOperation {
        ServiceOperation::Decrypt {
            authorization: self.authorization(NETWORK, *self.wallet.pubkey().as_bytes(), items),
            items: items.to_vec(),
        }
    }

    /// Opens a sealed answer to `items` with the wallet's own viewing secret.
    fn unseal(&self, result: ServiceResult, items: &[DecryptItem]) -> DecryptedOutputs {
        let ServiceResult::Sealed { enc, ciphertext } = result else {
            panic!("expected a Sealed result");
        };
        let secret = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(
            self.wallet.secret_bytes().as_slice(),
        )
        .unwrap();
        let aad = [self.address(), decrypt_items_digest(items).unwrap()].concat();
        let outputs = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &secret,
            &<X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc).unwrap(),
            SEALED_OUTPUTS_INFO,
            &ciphertext,
            &aad,
        )
        .unwrap();
        parse_strict_json(std::str::from_utf8(&outputs).unwrap()).unwrap()
    }
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
    let owner = Owner::new(5);
    let (viewing, nullifier) = owner.public_keys(&service, &seed);
    assert_ne!(viewing, Owner::new(9).public_keys(&service, &seed).0);

    // The second output is for another key, as a dummy under the owner's tag is.
    let stranger = *ViewingKey::new().pubkey().as_bytes();
    let items = [
        sent(viewing, viewing, b"ten usdc", 3),
        sent(stranger, viewing, b"not ours", 4),
    ];
    let request = request(&service, Some(seed), owner.decrypt(&items));
    let outputs = owner.unseal(call(&service, &request).unwrap(), &items);

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
fn a_batch_needs_the_owner_signature_for_this_network_wallet_key_and_batch() {
    let service = service();
    let seed = genesis(&service);
    let owner = Owner::new(5);
    let (viewing, _) = owner.public_keys(&service, &seed);
    let wallet = *owner.wallet.pubkey().as_bytes();
    let items = vec![sent(viewing, viewing, b"ten usdc", 0)];
    let valid = owner.authorization(NETWORK, wallet, &items);

    let mut other_signer = valid.clone();
    other_signer.signer = Owner::new(9).base58();
    let mut other_wallet = valid.clone();
    other_wallet.wallet_viewing_public_key = *Owner::new(9).wallet.pubkey().as_bytes();
    let mut tampered = valid.clone();
    tampered.signature[0] ^= 1;
    for authorization in [
        owner.authorization(other(NETWORK), wallet, &items),
        other_signer,
        other_wallet,
        tampered,
    ] {
        let items = items.clone();
        refused(
            &service,
            Some(&seed),
            ServiceOperation::Decrypt {
                authorization,
                items,
            },
        );
    }

    // A signature covers one batch.
    refused(
        &service,
        Some(&seed),
        ServiceOperation::Decrypt {
            authorization: valid,
            items: vec![sent(viewing, viewing, b"ten usdc", 1)],
        },
    );
}

#[test]
fn a_batch_holds_items_under_the_signers_service_viewing_key() {
    let service = service();
    let seed = genesis(&service);
    let owner = Owner::new(5);
    let (viewing, _) = owner.public_keys(&service, &seed);
    let (stranger, _) = Owner::new(9).public_keys(&service, &seed);
    for items in [Vec::new(), vec![sent(viewing, stranger, b"ten usdc", 0)]] {
        refused(&service, Some(&seed), owner.decrypt(&items));
    }
}

#[test]
fn an_answer_is_sealed_only_to_a_canonical_contributory_viewing_key() {
    let service = service();
    let seed = genesis(&service);
    let owner = Owner::new(5);
    let (viewing, _) = owner.public_keys(&service, &seed);
    let items = vec![sent(viewing, viewing, b"ten usdc", 0)];
    let mut wrong_tag = *owner.wallet.pubkey().as_bytes();
    wrong_tag[0] = 0x05;
    let mut non_canonical = [0xff; 33];
    non_canonical[0] = 0x04;
    let mut low_order = [0u8; 33];
    low_order[0] = 0x04;
    for wallet in [wrong_tag, non_canonical, low_order] {
        // The owner signed for the key, so only the key itself is at fault.
        refused(
            &service,
            Some(&seed),
            ServiceOperation::Decrypt {
                authorization: owner.authorization(NETWORK, wallet, &items),
                items: items.clone(),
            },
        );
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
            Some(&seed),
            ServiceOperation::PublicKeys { address },
        );
    }
}

#[test]
fn a_sealed_seed_is_one_this_enclave_drew_for_its_quorum_key_and_network() {
    let service = service();
    let seed = genesis(&service);
    assert_ne!(seed, genesis(&service), "every Genesis draws another seed");
    let public_keys = || ServiceOperation::PublicKeys {
        address: Owner::new(5).base58(),
    };

    let mut tampered = seed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    refused(&service, None, public_keys());
    refused(&service, Some(&tampered), public_keys());
    // Anyone can encrypt a seed they know to the Quorum key; only the enclave signs one.
    refused(
        &service,
        Some(&seed::forged(&service, [9; 32])),
        public_keys(),
    );
    refused(&service, Some(&seed), ServiceOperation::Genesis);
    refused(&service_on(NETWORK, 2), Some(&seed), public_keys());
    refused(&service_on(other(NETWORK), 1), Some(&seed), public_keys());
}

#[test]
fn a_request_is_bound_to_the_running_release() {
    let service = service();
    let seed = genesis(&service);
    let base = request(
        &service,
        Some(seed),
        ServiceOperation::PublicKeys {
            address: Owner::new(5).base58(),
        },
    );
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
        assert_eq!(call(&service, &request).unwrap_err(), Failure::Invalid);
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
async fn the_router_advertises_and_serves_the_three_operations() {
    let service = service();
    let response = router(service.clone())
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let info: ServiceInfo = parse_strict_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let (result, _) = open(&service, &request, std::str::from_utf8(&bytes).unwrap());
    assert!(matches!(result, ServiceResult::Genesis { .. }));
}
