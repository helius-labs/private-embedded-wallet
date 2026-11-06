use std::sync::Arc;

use qos_p256::P256Pair;
use spr_keypair::SigningKey;
use spr_prover_tee::{
    Anchors, FixtureProver, FreshnessSigners, NitroFixture, PolicySigners, ReleasePayload,
    SignedPolicyFile, TeePolicy,
};
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES, MAX_ENCRYPTED_RESPONSE_BYTES, MAX_PROVE_INPUTS,
    TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::types::{
    ClientAuthorization, ClientAuthorizationScheme, ClientGrant, DecryptItem, DecryptLabel,
    DeriveItem, ProverSealing, ServiceInfo, TransactionKeyItem, WalletDescriptor,
};

use zolana_tvc_protocol::digest::sealed_seed_digest;

use super::sealed::{seal, unseal, Roles};
use super::*;
use crate::custody::TurnkeyCustody;

/// A wallet key plus the seed its derivation message signs to.
struct TestWallet {
    secret: [u8; 32],
    public_key: [u8; 32],
    seed: [u8; 64],
}

fn test_wallet() -> TestWallet {
    let secret = *SigningKey::new_ed25519().secret_bytes();
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let public_key = key.verifying_key().to_bytes();
    let message = spr_keypair::derivation::ed25519_derivation_message(&public_key);
    let seed = ed25519_dalek::Signer::sign(&key, &message).to_bytes();
    TestWallet {
        secret,
        public_key,
        seed,
    }
}

/// The failure of a result whose success value has no `Debug`.
fn failure<T>(result: Result<T, Failure>) -> Failure {
    match result {
        Ok(_) => panic!("expected a failure"),
        Err(failure) => failure,
    }
}

fn runtime() -> Runtime {
    let quorum = Arc::new(P256Pair::generate().expect("quorum"));
    Runtime {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        custody: Arc::new(TurnkeyCustody::new(Arc::clone(&quorum))),
        quorum,
        provisioning_public: PROVISIONING_PUBLIC,
        grant_public: GRANT_PUBLIC,
        prover: production_prover_trust(),
    }
}

fn production_prover_trust() -> ProverTrust {
    ProverTrust::image()
}

const POLICY_SEED: [u8; 32] = [0x99; 32];
const ATTESTED_AT_SECS: u64 = 1_800_000_000;
const ATTESTED_AT_MS: u64 = ATTESTED_AT_SECS * 1_000;

fn policy_signer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&POLICY_SEED)
}

/// A fixture prover attested for one nonce, the trust that accepts it, and
/// a sealing that names it under a policy file `POLICY_SEED` signed.
struct ProverCase {
    prover: FixtureProver,
    trust: ProverTrust,
    sealing: ProverSealing,
}

fn prover_case(target: &str) -> ProverCase {
    let prover = FixtureProver::from_ikm(&[0x5a; 32]);
    let nonce = [0x11; 32];
    let fixture =
        NitroFixture::at(nonce, ATTESTED_AT_SECS).with_hpke_public_key(prover.hpke_public_key());
    let policy = signed_policy(
        &policy_signer(),
        NETWORK,
        fixture.policy().clone(),
        ATTESTED_AT_SECS + 60,
    );
    ProverCase {
        trust: ProverTrust {
            signers: PolicySigners::new(
                NETWORK,
                vec![policy_signer().verifying_key().to_bytes()],
                1,
            )
            .expect("signers"),
            anchors: fixture.anchors(),
        },
        sealing: ProverSealing {
            target: target.to_owned(),
            nonce,
            attestation: fixture.attestation_json(),
            policy,
        },
        prover,
    }
}

/// A policy file as a network publishes it, signed by `signer`.
fn signed_policy(
    signer: &ed25519_dalek::SigningKey,
    network: &str,
    policy: TeePolicy,
    expires_at: u64,
) -> serde_json::Value {
    const FRESHNESS_SECS: u64 = 3_600;
    // A freshness key the release names, distinct from its signer.
    let mut seed = signer.to_bytes();
    seed[0] ^= 0xff;
    let freshness = ed25519_dalek::SigningKey::from_bytes(&seed);
    let release = ReleasePayload {
        network: network.to_owned(),
        version: 1,
        expires_at,
        freshness: FreshnessSigners::of(std::slice::from_ref(&freshness), FRESHNESS_SECS),
        policy,
    };
    let fresh = (expires_at.saturating_sub(FRESHNESS_SECS), expires_at);
    let file = SignedPolicyFile::sign(&release, std::slice::from_ref(signer), fresh, &[freshness])
        .expect("policy file");
    serde_json::to_value(file).expect("policy file")
}

/// The policy a case's file approves, for a test that re-signs an edit of it.
fn approved_policy(case: &ProverCase) -> TeePolicy {
    let file: SignedPolicyFile =
        serde_json::from_value(case.sealing.policy.clone()).expect("policy file");
    let release: ReleasePayload =
        serde_json::from_slice(&hex::decode(&file.release.payload).expect("hex")).expect("release");
    release.policy
}

fn merge_request() -> serde_json::Value {
    serde_json::json!({
        "circuitType": "merge",
        "inputs": [{ "nullifier": "0x1" }],
        "userNullifierSecret": null,
    })
}

fn seal_case(
    case: &ProverCase,
) -> Result<zolana_tvc_protocol::types::SealedProverRequest, Failure> {
    prove::seal(
        &merge_request(),
        &[0x0a; 32],
        &case.sealing,
        &case.trust,
        ATTESTED_AT_MS,
    )
}

fn descriptor(address: [u8; 32]) -> WalletDescriptor {
    WalletDescriptor {
        version: API_VERSION,
        security_domain_id: [0x11; 32],
        environment: Environment::Development,
        turnkey_organization_id: "00000000-0000-0000-0000-00000000000b".to_owned(),
        turnkey_wallet_id: "test".to_owned(),
        address: Pubkey::new_from_array(address).to_string(),
        allowed_clients: vec![ClientGrant {
            client_public_key: vec![0x04; 65],
            allowed_operations: OPERATIONS.to_vec(),
        }],
        provisioning_signature: vec![0u8; 64],
    }
}

fn request(operation: Operation, descriptor: WalletDescriptor) -> OperationRequest {
    OperationRequest {
        version: API_VERSION,
        request_id: [0x01; 32],
        issued_at_ms: 1_750_000_000_000,
        expires_at_ms: 1_750_000_060_000,
        target_release_id: "test".to_owned(),
        target_manifest_digest: [0x33; 32],
        target_executable_digest: [0x44; 32],
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        wallet_descriptor: descriptor,
        sealed_seed: None,
        client_response_public_key: vec![0u8; 65],
        operation,
        authorization: ClientAuthorization {
            client_key_id: "tvc-browser-p256-test".to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: vec![0u8; 64],
        },
    }
}

fn sealed_request(
    runtime: &Runtime,
    wallet: &TestWallet,
    operation: Operation,
) -> OperationRequest {
    let mut request = request(operation, descriptor(wallet.public_key));
    let (bytes, _) = seal(&request, runtime, wallet.public_key, wallet.seed).expect("seal");
    request.sealed_seed = Some(bytes);
    request
}

#[test]
fn roles_come_only_from_the_wallets_own_derivation_signature() {
    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let address = roles.address().expect("address");
    assert_eq!(address.signing_pubkey, roles.owner);
    assert_eq!(address.viewing_pubkey, roles.viewing_key.pubkey());

    let other = test_wallet();
    assert_eq!(
        failure(Roles::from_seed(&other.public_key, &wallet.seed)),
        Failure::Invalid
    );
    let mut tampered = wallet.seed;
    tampered[7] ^= 1;
    assert_eq!(
        failure(Roles::from_seed(&wallet.public_key, &tampered)),
        Failure::Invalid
    );
}

#[test]
fn sealed_seed_hides_the_seed_and_is_bound_to_descriptor_and_epoch() {
    let runtime = runtime();
    let wallet = test_wallet();
    let request = sealed_request(&runtime, &wallet, derive_nothing());
    let sealed = request.sealed_seed.clone().expect("sealed");
    assert!(!sealed.windows(64).any(|window| window == wallet.seed));

    let (roles, digest) = unseal(&request, &runtime).expect("unseal");
    assert_eq!(digest, sealed_seed_digest(&sealed));
    assert_eq!(
        roles.address().expect("address"),
        Roles::from_seed(&wallet.public_key, &wallet.seed)
            .expect("roles")
            .address()
            .expect("address")
    );

    let mut other_epoch = request.clone();
    other_epoch.quorum_key_epoch = 2;
    assert_eq!(failure(unseal(&other_epoch, &runtime)), Failure::Invalid);

    let mut other_descriptor = request.clone();
    other_descriptor.wallet_descriptor.turnkey_wallet_id = "other".to_owned();
    assert_eq!(
        failure(unseal(&other_descriptor, &runtime)),
        Failure::Invalid
    );

    let mut other_grant = request.clone();
    other_grant.wallet_descriptor.allowed_clients[0].client_public_key = vec![0x05; 65];
    assert_eq!(failure(unseal(&other_grant, &runtime)), Failure::Invalid);

    let other_quorum = runtime_with_quorum(P256Pair::generate().expect("quorum"));
    assert_eq!(failure(unseal(&request, &other_quorum)), Failure::Invalid);

    let mut unsealed = request;
    unsealed.sealed_seed = None;
    assert_eq!(failure(unseal(&unsealed, &runtime)), Failure::Invalid);
}

fn runtime_with_quorum(quorum: P256Pair) -> Runtime {
    let quorum = Arc::new(quorum);
    Runtime {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        custody: Arc::new(TurnkeyCustody::new(Arc::clone(&quorum))),
        quorum,
        provisioning_public: PROVISIONING_PUBLIC,
        grant_public: GRANT_PUBLIC,
        prover: production_prover_trust(),
    }
}

#[test]
fn the_same_seed_reseals_under_a_new_quorum_key_to_the_same_identity() {
    let wallet = test_wallet();
    let first = runtime();
    let second = runtime();
    let a = sealed_request(&first, &wallet, derive_nothing());
    let b = sealed_request(&second, &wallet, derive_nothing());
    assert_ne!(a.sealed_seed, b.sealed_seed);
    let (roles_a, _) = unseal(&a, &first).expect("first");
    let (roles_b, _) = unseal(&b, &second).expect("second");
    assert_eq!(
        roles_a.address().expect("address"),
        roles_b.address().expect("address")
    );
    assert_eq!(failure(unseal(&a, &second)), Failure::Invalid);
}

/// A stateful operation with nothing in it, for tests about the envelope.
fn derive_nothing() -> Operation {
    Operation::Derive { items: Vec::new() }
}

#[test]
fn decrypt_applies_the_transfer_cipher_under_the_named_viewing_key() {
    use spr_keypair::{random_salt, ViewingKey};

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let transaction_key = ViewingKey::new();
    let salt = random_salt();
    let plaintext = b"opaque to the enclave".to_vec();
    let item = |recipient: &ViewingKey, slot: u32| DecryptItem {
        ciphertext: transaction_key
            .encrypt_slot(&recipient.pubkey(), &plaintext, salt, slot)
            .expect("ciphertext"),
        viewing_public_key: roles.viewing_key.pubkey().as_bytes().to_vec(),
        transaction_viewing_public_key: transaction_key.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: u64::from(slot),
        label: DecryptLabel::Transfer,
    };
    let ring_deposit = DecryptItem {
        ciphertext: transaction_key
            .encrypt_ring_deposit(&roles.viewing_key.pubkey(), &plaintext, salt)
            .expect("ciphertext"),
        slot_index: 0,
        label: DecryptLabel::RingDeposit,
        ..item(&roles.viewing_key, 0)
    };

    let OperationResult::Decrypt { plaintexts } = keys::decrypt(
        &roles,
        &[
            item(&roles.viewing_key, 1),
            item(&ViewingKey::new(), 2),
            ring_deposit,
        ],
    )
    .expect("decrypt") else {
        panic!("expected plaintexts");
    };
    // The cipher is unauthenticated: another wallet's slot answers with bytes
    // that are not the plaintext, never with an error.
    assert_eq!(plaintexts.len(), 3);
    assert_eq!(plaintexts[0], plaintext);
    assert_ne!(plaintexts[1], plaintext);
    assert_eq!(plaintexts[2], plaintext);

    assert_eq!(failure(keys::decrypt(&roles, &[])), Failure::Invalid);
    let stranger = DecryptItem {
        viewing_public_key: ViewingKey::new().pubkey().as_bytes().to_vec(),
        ..item(&roles.viewing_key, 1)
    };
    assert_eq!(
        failure(keys::decrypt(&roles, &[stranger])),
        Failure::Invalid
    );
    let mut truncated = item(&roles.viewing_key, 1);
    truncated.transaction_viewing_public_key.pop();
    assert_eq!(
        failure(keys::decrypt(&roles, &[truncated])),
        Failure::Invalid
    );
    // Only the X25519 tag names a transaction key.
    let mut untagged = item(&roles.viewing_key, 1);
    untagged.transaction_viewing_public_key[0] = 0x02;
    assert_eq!(
        failure(keys::decrypt(&roles, &[untagged])),
        Failure::Invalid
    );
    let ring_slot = DecryptItem {
        slot_index: 1,
        label: DecryptLabel::RingDeposit,
        ..item(&roles.viewing_key, 1)
    };
    assert_eq!(
        failure(keys::decrypt(&roles, &[ring_slot])),
        Failure::Invalid
    );
}

#[test]
fn derive_answers_the_nullifier_and_merge_derivations() {
    use spr_transaction::instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_output_key, merge_private_tx_blinding,
    };

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let utxo_hash = [3u8; 32];
    let blinding = [4u8; 32];
    let first_nullifier = [5u8; 32];
    let OperationResult::Derive { values } = keys::derive(
        &roles,
        &[
            DeriveItem::Nullifier {
                utxo_hash,
                blinding,
            },
            DeriveItem::MergeDummyNullifier {
                first_nullifier,
                slot_index: 3,
            },
            DeriveItem::MergeOutputBlinding { first_nullifier },
            DeriveItem::MergePrivateTxBlinding { first_nullifier },
            DeriveItem::MergeOutputKey { first_nullifier },
        ],
    )
    .expect("derive") else {
        panic!("expected values");
    };
    assert_eq!(
        values,
        vec![
            roles
                .nullifier_key
                .nullifier(&utxo_hash, &blinding)
                .expect("nullifier"),
            merge_dummy_nullifier(&roles.nullifier_key, &first_nullifier, 3).expect("dummy"),
            merge_output_blinding(&roles.nullifier_key, &first_nullifier).expect("blinding"),
            merge_private_tx_blinding(&roles.nullifier_key, &first_nullifier)
                .expect("private transaction blinding"),
            merge_output_key(&roles.nullifier_key, &first_nullifier).expect("output key"),
        ]
    );
    assert_eq!(
        failure(keys::derive(
            &roles,
            &[DeriveItem::MergeDummyNullifier {
                first_nullifier,
                slot_index: 256,
            }]
        )),
        Failure::Invalid
    );
    assert_eq!(failure(keys::derive(&roles, &[])), Failure::Invalid);
}

#[test]
fn transaction_keys_are_the_per_transaction_viewing_secrets() {
    use spr_keypair::ViewingKey;

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let first_nullifier = [9u8; 32];
    let item = TransactionKeyItem {
        viewing_public_key: roles.viewing_key.pubkey().as_bytes().to_vec(),
        first_nullifier,
    };
    let OperationResult::TransactionKeys { secrets } =
        keys::transaction_keys(&roles, std::slice::from_ref(&item)).expect("keys")
    else {
        panic!("expected secrets");
    };
    let expected = roles
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .expect("transaction key");
    assert_eq!(secrets, vec![*expected.secret_bytes()]);
    // The secret is a key in its own right and not the viewing secret.
    assert_eq!(
        ViewingKey::from_bytes(&secrets[0]).pubkey(),
        expected.pubkey()
    );
    assert_ne!(secrets[0], *roles.viewing_key.secret_bytes());

    let stranger = TransactionKeyItem {
        viewing_public_key: ViewingKey::new().pubkey().as_bytes().to_vec(),
        ..item
    };
    assert_eq!(
        failure(keys::transaction_keys(&roles, &[stranger])),
        Failure::Invalid
    );
}

#[test]
fn proving_key_names_the_key_file_of_the_circuit_shape() {
    use serde_json::json;

    let transfer = |circuit: &str, inputs: usize, outputs: usize| {
        json!({
            "circuitType": circuit,
            "inputs": vec![json!({}); inputs],
            "outputs": vec![json!({}); outputs],
        })
    };
    let merge = |circuit: &str, inputs: usize| json!({ "circuitType": circuit, "inputs": vec![json!({}); inputs] });
    for (body, key) in [
        (
            transfer("transfer-confidential", 2, 2),
            "transfer_confidential_2_2",
        ),
        (
            transfer("transfer-confidential", 12, 16),
            "transfer_confidential_12_16",
        ),
        (transfer("transfer-ring", 1, 2), "transfer_ring_1_2"),
        (merge("merge", 8), "merge_8_1"),
        (merge("merge", 52), "merge_52_1"),
        (merge("merge-ring", 52), "merge_ring_52_1"),
    ] {
        assert_eq!(prove::proving_key(&body).expect("key"), key);
    }
    for body in [
        // A circuit the wallet never proves.
        transfer("transfer-ring-authority", 1, 2),
        json!({ "circuitType": "custom-ring-policy" }),
        // Slot counts outside the installed keys.
        transfer("transfer-confidential", 0, 2),
        transfer("transfer-confidential", 2, 0),
        merge("merge", MAX_PROVE_INPUTS + 1),
        json!({ "circuitType": "transfer-confidential", "inputs": [{}], "outputs": "0x2" }),
        json!("not an object"),
    ] {
        assert_eq!(
            failure(prove::proving_key(&body)),
            Failure::Invalid,
            "{body}"
        );
    }
}

#[test]
fn prove_fills_only_the_open_secret_slots() {
    use serde_json::json;

    let secret = [0x0a; 31];
    // The prover's field encoding: no leading zero digits.
    let filled = "0x".to_owned() + "0a".repeat(31).trim_start_matches('0');
    let transfer = json!({
        "circuitType": "transfer-confidential",
        "nInputs": 2,
        "inputs": [
            { "isDummy": "0x0", "nullifierSecret": null, "nullifier": "0x1" },
            { "isDummy": "0x1", "nullifierSecret": "0x0", "nullifier": "0x2" },
        ],
        "outputs": [],
    });
    let complete = prove::complete(&transfer, &secret).expect("complete");
    assert_eq!(complete["inputs"][0]["nullifierSecret"], filled);
    assert_eq!(complete["inputs"][1]["nullifierSecret"], "0x0");
    // Nothing else moves.
    let mut expected = transfer.clone();
    expected["inputs"][0]["nullifierSecret"] = json!(filled);
    assert_eq!(complete, expected);

    let merge = json!({
        "circuitType": "merge",
        "inputs": [{ "nullifier": "0x1" }],
        "userNullifierPk": "0x3",
        "userNullifierSecret": null,
    });
    let complete = prove::complete(&merge, &secret).expect("complete");
    assert_eq!(complete["userNullifierSecret"], filled);

    // A leading zero byte in the secret is not written: fields are integers.
    let mut short = [0u8; 31];
    short[30] = 0x0f;
    assert_eq!(
        prove::complete(&merge, &short).expect("complete")["userNullifierSecret"],
        "0xf"
    );

    for body in [
        // Nothing to fill.
        json!({ "circuitType": "merge", "inputs": [{}], "userNullifierSecret": "0x1" }),
        // Unknown circuit.
        json!({ "circuitType": "custom-ring", "inputs": [{}] }),
        // The secret asked for in a padding slot.
        json!({ "circuitType": "transfer-ring", "inputs": [{ "isDummy": "0x1", "nullifierSecret": null }] }),
        // A slot of the wrong shape.
        json!({ "circuitType": "transfer-ring", "inputs": [{ "isDummy": "0x0", "nullifierSecret": 7 }] }),
        // No inputs, too many inputs.
        json!({ "circuitType": "transfer-confidential", "inputs": [] }),
        json!({ "circuitType": "merge", "inputs": vec![json!({}); MAX_PROVE_INPUTS + 1], "userNullifierSecret": null }),
        json!("not an object"),
    ] {
        assert_eq!(
            failure(prove::complete(&body, &secret)),
            Failure::Invalid,
            "{body}"
        );
    }
}

/// The image builds the signer set zolana pins for its network.
#[test]
fn the_image_trusts_the_networks_policy_signers() {
    let image = ProverTrust::image();
    let expected = PolicySigners::new(
        NETWORK,
        vec![hex::decode(POLICY_SIGNERS[0]).unwrap().try_into().unwrap()],
        POLICY_THRESHOLD,
    )
    .unwrap();
    assert_eq!(image.signers, expected);
}

#[test]
fn prove_seals_the_completed_request_to_the_attested_prover() {
    let case = prover_case("/prove/merge_1_1");
    let sealed = seal_case(&case).expect("sealed");
    assert_eq!(sealed.target, "/prove/merge_1_1");

    let opened = case
        .prover
        .open("POST", &sealed.target, &sealed.enc, &sealed.ciphertext)
        .expect("opens on its route");
    case.prover
        .open(
            "POST",
            "/v1/spr/prove/merge_1_1",
            &sealed.enc,
            &sealed.ciphertext,
        )
        .expect("opens on its route under the gateway prefix");
    let witness: serde_json::Value = serde_json::from_slice(&opened.plaintext).expect("json");
    assert_eq!(
        witness["userNullifierSecret"],
        format!("0x{}", "0a".repeat(32).trim_start_matches('0'))
    );
    assert_eq!(opened.response_key, sealed.response_key);
    assert!(case
        .prover
        .open("POST", "/prove/merge_8_1", &sealed.enc, &sealed.ciphertext)
        .is_err());
}

#[test]
fn prove_refuses_a_prover_outside_the_signed_policy() {
    type Edit = fn(&mut ProverCase);
    let cases: &[(&str, Edit)] = &[
        ("policy signed by another key", |case| {
            let other = ed25519_dalek::SigningKey::from_bytes(&[0x98; 32]);
            let policy = approved_policy(case);
            case.sealing.policy = signed_policy(&other, NETWORK, policy, ATTESTED_AT_SECS + 60);
        }),
        ("policy of another network", |case| {
            let policy = approved_policy(case);
            case.sealing.policy =
                signed_policy(&policy_signer(), "localnet", policy, ATTESTED_AT_SECS + 60);
        }),
        ("expired policy", |case| {
            let policy = approved_policy(case);
            case.sealing.policy =
                signed_policy(&policy_signer(), NETWORK, policy, ATTESTED_AT_SECS);
        }),
        ("edited release payload", |case| {
            let release = &mut case.sealing.policy["release"];
            let payload = release["payload"].as_str().unwrap().to_owned();
            release["payload"] = serde_json::json!(payload.replacen("7b", "7b20", 1));
        }),
        ("the image's own signers", |case| {
            case.trust.signers = ProverTrust::image().signers
        }),
        ("attestation for another nonce", |case| {
            case.sealing.nonce = [0x12; 32]
        }),
        ("measurement the policy does not pin", |case| {
            let mut tee = serde_json::to_value(approved_policy(case)).unwrap();
            tee["measurements"][0]["pcr0"] = serde_json::json!("04".repeat(48));
            let policy = serde_json::from_value(tee).unwrap();
            case.sealing.policy =
                signed_policy(&policy_signer(), NETWORK, policy, ATTESTED_AT_SECS + 60);
        }),
        ("evidence under a root the enclave does not trust", |case| {
            case.trust.anchors = Anchors::PRODUCTION
        }),
        ("an attestation without evidence", |case| {
            case.sealing.attestation = serde_json::json!({ "platform": "aws-nitro" })
        }),
    ];
    for (name, edit) in cases {
        let mut case = prover_case("/prove/merge_1_1");
        edit(&mut case);
        assert_eq!(
            failure(seal_case(&case)),
            Failure::Stage(FailureStage::Prover),
            "{name}"
        );
    }
}

#[test]
fn prove_binds_only_the_route_of_the_requests_proving_key() {
    seal_case(&prover_case("/prove/merge_1_1")).expect("the route");
    for target in [
        "/v1/spr/prove/merge_1_1",
        "/v1/zolana/prove/merge_1_1",
        "/prove/merge_8_1",
        "/prove/merge_1_1?jobId=1",
        "/prove/merge_1_1/",
        "/prove/merge_1_1/status",
        "//prove/merge_1_1",
        "prove/merge_1_1",
        "",
    ] {
        assert_eq!(
            failure(seal_case(&prover_case(target))),
            Failure::Invalid,
            "{target}"
        );
    }
}

fn unavailable_state() -> AppState {
    AppState::unavailable(ServiceInfo {
        version: API_VERSION,
        environment: Environment::Development,
        security_domain_id: [0; 32],
        release_id: "test".to_owned(),
        manifest_digest: [0; 32],
        executable_digest: [0; 32],
        quorum_public_key: Vec::new(),
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        ephemeral_public_key: Vec::new(),
        supported_operations: OPERATIONS.to_vec(),
        max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
        boot_proof_lookup_key: Vec::new(),
    })
}

/// The release [`request`] is bound to.
fn running() -> RunningEnclave {
    RunningEnclave {
        release_id: "test".to_owned(),
        manifest_digest: [0x33; 32],
        executable_digest: [0x44; 32],
        security_domain_id: [0x11; 32],
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        environment: Environment::Development,
    }
}

#[test]
fn a_request_bound_to_another_release_or_quorum_key_is_refused() {
    use zolana_tvc_protocol::error::ErrorCode;

    let running = running();
    let bound = request(derive_nothing(), descriptor([0x07; 32]));
    assert_eq!(check_request_bindings(&bound, &running), Ok(()));
    type Edit = fn(&mut OperationRequest);
    let cases: [(Edit, ErrorCode); 6] = [
        (
            |request| request.quorum_key_epoch = 9,
            ErrorCode::QuorumKeyEpochMismatch,
        ),
        (
            |request| request.target_release_id = "other-release".to_owned(),
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.target_manifest_digest = [0xcc; 32],
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.target_executable_digest = [0xdd; 32],
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.quorum_key_id = "other-quorum".to_owned(),
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.wallet_descriptor.turnkey_wallet_id.clear(),
            ErrorCode::InvalidWalletDescriptor,
        ),
    ];
    for (edit, code) in cases {
        let mut request = bound.clone();
        edit(&mut request);
        assert_eq!(
            check_request_bindings(&request, &running).map_err(|error| error.code),
            Err(code)
        );
    }
}

#[test]
fn bootstrap_refuses_a_presented_state_and_the_rest_require_one() {
    let runtime = runtime();
    let wallet = test_wallet();
    let running = running();
    let state = unavailable_state();
    let with_state = sealed_request(&runtime, &wallet, Operation::Bootstrap);
    assert_eq!(
        failure(validate(&with_state, &running, &state, &runtime)),
        Failure::Invalid
    );
    for operation in [
        derive_nothing(),
        Operation::Decrypt { items: Vec::new() },
        Operation::TransactionKeys { items: Vec::new() },
        Operation::Prove {
            request: serde_json::Value::Null,
            prover: Box::new(prover_case("/prove/merge_1_1").sealing),
        },
    ] {
        let without_state = request(operation, descriptor(wallet.public_key));
        assert_eq!(
            failure(validate(&without_state, &running, &state, &runtime)),
            Failure::Invalid
        );
    }
}

#[test]
fn organization_ids_must_be_canonical_uuids() {
    assert!(is_canonical_uuid("00000000-0000-4000-8000-000000000001"));
    assert!(!is_canonical_uuid("00000000-0000-4000-8000-00000000000A"));
    assert!(!is_canonical_uuid("00000000000040008000000000000001"));
    assert!(!is_canonical_uuid("child-org"));
}

#[cfg(feature = "local-dev")]
mod local {
    //! The whole encrypted path against the testkit's local custody.

    use qos_p256::P256Pair;
    use serde::Deserialize;
    use spr_prover_tee::{decrypt_response, ATTESTATION_PATH, HEADER_ENC, HEADER_VERSION, VERSION};
    use zolana_tvc_protocol::auth::authorize_operation_request;
    use zolana_tvc_protocol::constants::MAX_CLOCK_SKEW_MS;
    use zolana_tvc_protocol::crypto::{
        parse_uncompressed_sec1, public_key_uncompressed, qos_decrypt, qos_encrypt,
        sign_p256_prehash, verify_p256_message, QosP256Public,
    };
    use zolana_tvc_protocol::digest::{descriptor_digest, request_digest, result_digest, sha256};
    use zolana_tvc_protocol::encoding::{decode_lower_hex_array, jcs_serialize, parse_strict_json};
    use zolana_tvc_protocol::sign_wallet_grant;
    use zolana_tvc_protocol::types::{
        EncryptedRequest, EncryptedResponse, OperationProofPayload, SealedProverRequest,
        WalletGrant,
    };

    use super::*;
    use crate::{
        local_testkit_qos_seeds, local_unattested_state, LocalProver, LocalProverTrust, POLICY_PATH,
    };

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Keys {
        provisioning_private_key_hex: String,
        grant_private_key_hex: String,
        client_private_key_hex: String,
        organization_id: String,
        wallet_id: String,
        security_domain_label: String,
        manifest_label: String,
        executable_label: String,
        release_id: String,
        quorum_key_id: String,
    }

    struct Harness {
        state: AppState,
        keys: Keys,
        wallet: TestWallet,
        client_secret: [u8; 32],
        response_secret: [u8; 32],
    }

    impl Harness {
        fn new(prover: LocalProverTrust) -> Self {
            let keys: Keys = serde_json::from_str(include_str!(
                "../../../../packages/tvc-wallet/src/local-testkit.json"
            ))
            .expect("testkit");
            let (ephemeral_seed, quorum_seed) = local_testkit_qos_seeds();
            let wallet = test_wallet();
            let state = local_unattested_state(
                P256Pair::from_master_seed(&ephemeral_seed.into()).expect("ephemeral"),
                P256Pair::from_master_seed(&quorum_seed.into()).expect("quorum"),
                wallet.secret,
                prover,
            );
            Self {
                state,
                client_secret: decode_lower_hex_array(&keys.client_private_key_hex)
                    .expect("client"),
                response_secret: [0x42; 32],
                keys,
                wallet,
            }
        }

        fn descriptor(&self) -> WalletDescriptor {
            let client_public = public_key_uncompressed(
                &p256::SecretKey::from_slice(&self.client_secret)
                    .expect("client scalar")
                    .public_key(),
            );
            let mut descriptor = WalletDescriptor {
                version: API_VERSION,
                security_domain_id: sha256(self.keys.security_domain_label.as_bytes()),
                environment: Environment::Development,
                turnkey_organization_id: self.keys.organization_id.clone(),
                turnkey_wallet_id: self.keys.wallet_id.clone(),
                address: Pubkey::new_from_array(self.wallet.public_key).to_string(),
                allowed_clients: vec![ClientGrant {
                    client_public_key: client_public.to_vec(),
                    allowed_operations: OPERATIONS.to_vec(),
                }],
                provisioning_signature: Vec::new(),
            };
            let provisioning: [u8; 32] =
                decode_lower_hex_array(&self.keys.provisioning_private_key_hex)
                    .expect("provisioner");
            descriptor.provisioning_signature = sign_p256_prehash(
                &provisioning,
                &descriptor_digest(&descriptor).expect("digest"),
            )
            .expect("descriptor signature")
            .to_vec();
            descriptor
        }

        fn request(&self, operation: Operation, sealed: Option<Vec<u8>>) -> OperationRequest {
            let info = &self.state.info;
            let now = now_ms().expect("clock");
            let descriptor = self.descriptor();
            let client_key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
            let response_public = public_key_uncompressed(
                &p256::SecretKey::from_slice(&self.response_secret)
                    .expect("response scalar")
                    .public_key(),
            );
            let request = OperationRequest {
                version: API_VERSION,
                request_id: sha256(b"request"),
                issued_at_ms: now,
                expires_at_ms: now + 60_000,
                target_release_id: self.keys.release_id.clone(),
                target_manifest_digest: sha256(self.keys.manifest_label.as_bytes()),
                target_executable_digest: sha256(self.keys.executable_label.as_bytes()),
                quorum_key_id: self.keys.quorum_key_id.clone(),
                quorum_key_epoch: 1,
                wallet_descriptor: descriptor,
                sealed_seed: sealed,
                client_response_public_key: response_public.to_vec(),
                operation,
                authorization: ClientAuthorization {
                    client_key_id,
                    scheme: ClientAuthorizationScheme::P256Sha256,
                    signature: Vec::new(),
                },
            };
            assert_eq!(info.release_id, request.target_release_id);
            authorize_operation_request(request, &self.client_secret).expect("authorized")
        }

        /// A grant for `request`'s descriptor and client key, valid from
        /// `issued_at_ms` for `lifetime_ms`, signed by the testkit grant key.
        fn grant(
            &self,
            request: &OperationRequest,
            issued_at_ms: u64,
            lifetime_ms: u64,
        ) -> WalletGrant {
            let unsigned = WalletGrant {
                version: API_VERSION,
                descriptor_digest: descriptor_digest(&request.wallet_descriptor).expect("digest"),
                client_key_id: request.authorization.client_key_id.clone(),
                project_id: "local".to_owned(),
                issued_at_ms,
                expires_at_ms: issued_at_ms + lifetime_ms,
                signature: Vec::new(),
            };
            let secret: [u8; 32] =
                decode_lower_hex_array(&self.keys.grant_private_key_hex).expect("grant key");
            sign_wallet_grant(unsigned, &secret).expect("grant")
        }

        /// Sends one request, with a current grant, through the encrypted
        /// endpoint and opens the answer.
        async fn call(&self, request: &OperationRequest) -> Result<OperationResult, Failure> {
            let grant = self.grant(request, now_ms().expect("clock"), 900_000);
            self.call_with_grant(request, Some(grant)).await
        }

        async fn call_with_grant(
            &self,
            request: &OperationRequest,
            wallet_grant: Option<WalletGrant>,
        ) -> Result<OperationResult, Failure> {
            let quorum =
                QosP256Public::from_bytes(&self.state.info.quorum_public_key).expect("quorum");
            let ciphertext = qos_encrypt(
                &quorum.encryption,
                jcs_serialize(request).expect("request").as_bytes(),
            )
            .expect("encrypt");
            let body = jcs_serialize(&EncryptedRequest {
                version: API_VERSION,
                quorum_key_id: request.quorum_key_id.clone(),
                quorum_key_epoch: request.quorum_key_epoch,
                ciphertext,
                wallet_grant,
            })
            .expect("envelope");
            let response = execute(&self.state, body.as_bytes()).await?;
            let response: EncryptedResponse = parse_strict_json(&response).expect("response");
            assert_eq!(response.request_id, request.request_id);

            let proof = response.tvc_app_proof;
            let ephemeral = QosP256Public::from_bytes(&proof.public_key).expect("ephemeral");
            assert_eq!(proof.public_key, self.state.info.ephemeral_public_key);
            verify_p256_message(
                &ephemeral.signing,
                proof.proof_payload.as_bytes(),
                &proof.signature,
            )
            .expect("app proof signature");
            let payload: OperationProofPayload =
                parse_strict_json(&proof.proof_payload).expect("proof payload");
            assert_eq!(
                payload.request_digest,
                request_digest(request).expect("digest")
            );
            assert_eq!(
                payload.result_digest,
                result_digest(&response.encrypted_result)
            );
            assert_eq!(payload.operation, request.operation.kind());
            parse_uncompressed_sec1(&request.client_response_public_key).expect("response key");

            let plaintext =
                qos_decrypt(&self.response_secret, &response.encrypted_result).expect("result");
            Ok(
                parse_strict_json(std::str::from_utf8(plaintext.as_slice()).expect("utf8"))
                    .expect("result"),
            )
        }
    }

    #[tokio::test]
    async fn an_operation_needs_a_current_grant_for_its_descriptor_and_client_key() {
        let harness = Harness::new(LocalProverTrust::StandIn(Anchors::PRODUCTION));
        let request = harness.request(Operation::Bootstrap, None);
        let now = now_ms().expect("clock");

        assert_eq!(
            failure(harness.call_with_grant(&request, None).await),
            Failure::Invalid
        );

        let expired = harness.grant(&request, now - 1_800_000, 900_000 - MAX_CLOCK_SKEW_MS);
        assert_eq!(
            failure(harness.call_with_grant(&request, Some(expired)).await),
            Failure::Invalid
        );

        let mut other_wallet = harness.request(Operation::Bootstrap, None);
        other_wallet.wallet_descriptor.turnkey_wallet_id = "another-wallet".to_owned();
        let foreign = harness.grant(&other_wallet, now, 900_000);
        assert_eq!(
            failure(harness.call_with_grant(&request, Some(foreign)).await),
            Failure::Invalid
        );

        let mut forged = harness.grant(&request, now, 900_000);
        forged.signature = sign_wallet_grant(forged.clone(), &[0x77; 32])
            .expect("grant")
            .signature;
        assert_eq!(
            failure(harness.call_with_grant(&request, Some(forged)).await),
            Failure::Invalid
        );
    }

    /// A prover that answers `/prove/<key>` with a fixed proof once the
    /// request carries no open secret slot, and records the key and body it
    /// was sent.
    async fn mock_prover() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
    ) {
        use axum::body::Bytes;
        use axum::extract::Path;
        use axum::routing::post;
        use axum::Router;

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&seen);
        let app = Router::new().route(
            "/prove/{key}",
            post(move |Path(key): Path<String>, body: Bytes| {
                let recorded = std::sync::Arc::clone(&recorded);
                async move {
                    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
                    recorded.lock().expect("lock").push((key, body));
                    let proof = serde_json::json!({
                        "proof": { "ar": ["0x1", "0x2"], "bs": [["0x3", "0x4"], ["0x5", "0x6"]], "krs": ["0x7", "0x8"] }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(axum::http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(proof.to_string()))
                        .expect("response")
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (url, seen)
    }

    #[tokio::test]
    async fn bootstrap_then_every_key_operation_through_the_encrypted_endpoint() {
        let (upstream_url, seen) = mock_prover().await;
        let prover = LocalProver::new(&upstream_url);
        let harness = Harness::new(LocalProverTrust::StandIn(prover.anchors()));
        let prover_url = serve(prover.router()).await;
        let bootstrap = harness.request(Operation::Bootstrap, None);
        let OperationResult::Bootstrap {
            solana_address,
            shielded_owner_hash,
            shielded_viewing_public_key,
            sealed_seed,
            ..
        } = harness.call(&bootstrap).await.expect("bootstrap")
        else {
            panic!("expected a bootstrap result");
        };
        let roles =
            Roles::from_seed(&harness.wallet.public_key, &harness.wallet.seed).expect("roles");
        assert_eq!(
            solana_address,
            Pubkey::new_from_array(harness.wallet.public_key).to_string()
        );
        assert_eq!(
            shielded_owner_hash,
            roles
                .address()
                .expect("address")
                .owner_hash()
                .expect("owner hash")
        );
        assert!(!sealed_seed
            .windows(64)
            .any(|window| window == harness.wallet.seed));
        let sealed = || Some(sealed_seed.clone());

        let first_nullifier = [7u8; 32];
        let derive = harness.request(
            Operation::Derive {
                items: vec![DeriveItem::MergeOutputBlinding { first_nullifier }],
            },
            sealed(),
        );
        assert_eq!(
            harness.call(&derive).await.expect("derive"),
            keys::derive(
                &roles,
                &[DeriveItem::MergeOutputBlinding { first_nullifier }]
            )
            .expect("expected")
        );

        let transaction_keys = harness.request(
            Operation::TransactionKeys {
                items: vec![TransactionKeyItem {
                    viewing_public_key: shielded_viewing_public_key.clone(),
                    first_nullifier,
                }],
            },
            sealed(),
        );
        let OperationResult::TransactionKeys { secrets } =
            harness.call(&transaction_keys).await.expect("keys")
        else {
            panic!("expected transaction keys");
        };
        assert_eq!(
            secrets,
            vec![*roles
                .viewing_key
                .get_transaction_viewing_key(&first_nullifier)
                .expect("key")
                .secret_bytes()]
        );

        let prover_sealing = attest(&prover_url, "/prove/merge_1_1").await;
        let prove = harness.request(
            Operation::Prove {
                request: serde_json::json!({
                    "circuitType": "merge",
                    "inputs": [{ "nullifier": "0x1" }],
                    "userNullifierSecret": null,
                }),
                prover: Box::new(prover_sealing.clone()),
            },
            sealed(),
        );
        let OperationResult::Prove { sealed: request } = harness.call(&prove).await.expect("prove")
        else {
            panic!("expected a sealed request");
        };
        // The witness leaves the enclave only as ciphertext; the attested
        // prover opens it and answers under the response key.
        assert!(!request
            .ciphertext
            .windows(18)
            .any(|window| window == b"userNullifierSecre"));
        let proof = submit(&prover_url, &request).await;
        assert_eq!(proof["proof"]["ar"][0], "0x1");
        let expected_secret = format!(
            "0x{}",
            hex::encode(roles.nullifier_key.secret().as_slice()).trim_start_matches('0')
        );
        {
            let sent = seen.lock().expect("lock");
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].0, "merge_1_1");
            assert_eq!(sent[0].1["userNullifierSecret"], expected_secret);
        }

        // A bootstrap that presents a state, and a stateful operation that
        // presents none, are rejected before any key is touched.
        let stateful_bootstrap = harness.request(Operation::Bootstrap, sealed());
        assert_eq!(
            harness.call(&stateful_bootstrap).await.unwrap_err(),
            Failure::Invalid
        );
        let stateless_derive = harness.request(derive_nothing(), None);
        assert_eq!(
            harness.call(&stateless_derive).await.unwrap_err(),
            Failure::Invalid
        );
        // A prover request with nothing to fill is refused.
        let idle = harness.request(
            Operation::Prove {
                request: serde_json::json!({
                    "circuitType": "merge",
                    "inputs": [{}],
                    "userNullifierSecret": "0x1",
                }),
                prover: Box::new(prover_sealing),
            },
            sealed(),
        );
        assert_eq!(harness.call(&idle).await.unwrap_err(), Failure::Invalid);
        assert_eq!(seen.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn a_refused_attestation_is_a_failure_stage_inside_the_result() {
        let prover = LocalProver::new("http://127.0.0.1:1");
        let harness = Harness::new(LocalProverTrust::StandIn(prover.anchors()));
        let prover_url = serve(prover.router()).await;
        let bootstrap = harness.request(Operation::Bootstrap, None);
        let OperationResult::Bootstrap { sealed_seed, .. } =
            harness.call(&bootstrap).await.expect("bootstrap")
        else {
            panic!("expected a bootstrap result");
        };
        let mut sealing = attest(&prover_url, "/prove/merge_1_1").await;
        sealing.nonce = [0x43; 32];
        let prove = harness.request(
            Operation::Prove {
                request: serde_json::json!({
                    "circuitType": "merge",
                    "inputs": [{}],
                    "userNullifierSecret": null,
                }),
                prover: Box::new(sealing),
            },
            Some(sealed_seed),
        );
        assert_eq!(
            harness.call(&prove).await.expect("answered"),
            OperationResult::Failure {
                operation: OperationKind::Prove,
                stage: FailureStage::Prover,
            }
        );
    }

    /// A local enclave trusting the image's network refuses the stand-in's
    /// fixture attestation and the testkit-signed policy it publishes.
    #[tokio::test]
    async fn an_image_trusting_local_enclave_refuses_the_stand_in_prover() {
        let prover = LocalProver::new("http://127.0.0.1:1");
        let harness = Harness::new(LocalProverTrust::Image);
        let prover_url = serve(prover.router()).await;
        let bootstrap = harness.request(Operation::Bootstrap, None);
        let OperationResult::Bootstrap { sealed_seed, .. } =
            harness.call(&bootstrap).await.expect("bootstrap")
        else {
            panic!("expected a bootstrap result");
        };
        let prove = harness.request(
            Operation::Prove {
                request: serde_json::json!({
                    "circuitType": "merge",
                    "inputs": [{}],
                    "userNullifierSecret": null,
                }),
                prover: Box::new(attest(&prover_url, "/prove/merge_1_1").await),
            },
            Some(sealed_seed),
        );
        assert_eq!(
            harness.call(&prove).await.expect("answered"),
            OperationResult::Failure {
                operation: OperationKind::Prove,
                stage: FailureStage::Prover,
            }
        );
    }

    async fn serve(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });
        url
    }

    /// The sealing a client builds: the prover's attestation for a fresh
    /// nonce and the policy the stand-in prover publishes.
    async fn attest(prover_url: &str, target: &str) -> ProverSealing {
        let nonce = [0x42; 32];
        let attestation = reqwest::get(format!(
            "{prover_url}{ATTESTATION_PATH}?nonce={}",
            hex::encode(nonce)
        ))
        .await
        .expect("attestation")
        .json()
        .await
        .expect("attestation json");
        let policy = reqwest::get(format!("{prover_url}{POLICY_PATH}"))
            .await
            .expect("policy")
            .json()
            .await
            .expect("policy json");
        ProverSealing {
            target: target.to_owned(),
            nonce,
            attestation,
            policy,
        }
    }

    /// Posts a sealed request as a client does and opens the answer.
    async fn submit(prover_url: &str, sealed: &SealedProverRequest) -> serde_json::Value {
        let response = reqwest::Client::new()
            .post(format!("{prover_url}{}", sealed.target))
            .header(HEADER_VERSION, VERSION)
            .header(HEADER_ENC, hex::encode(sealed.enc))
            .body(sealed.ciphertext.clone())
            .send()
            .await
            .expect("submit");
        assert_eq!(
            response.headers().get(HEADER_VERSION).expect("encrypted"),
            VERSION
        );
        let encrypted = response.bytes().await.expect("answer");
        let (status, body) = decrypt_response(&sealed.response_key, &encrypted).expect("opens");
        assert_eq!(status, 200);
        serde_json::from_slice(&body).expect("proof json")
    }
}
