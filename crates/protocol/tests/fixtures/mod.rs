//! Committed, content-addressed protocol conformance fixtures.

use std::collections::BTreeMap;
use std::path::Path;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use zolana_tvc_protocol::auth::{authorize_operation_request, verify_client_authorization};
use zolana_tvc_protocol::constants::{
    API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID, MAX_ENCRYPTED_REQUEST_BYTES,
    MAX_ENCRYPTED_RESPONSE_BYTES, QOS_P256_PUBLIC_LEN, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{
    public_key_uncompressed, qos_decrypt, qos_encrypt_with, qos_public_from_secrets,
    sign_p256_prehash, verify_p256_prehash, verify_turnkey_app_proof_p256_message, QosP256Public,
};
use zolana_tvc_protocol::digest::{
    client_auth_digest, client_auth_message, descriptor_digest, request_digest, request_id_hash,
    result_digest, sealed_seed_digest, wallet_grant_digest, wallet_id_hash,
};
use zolana_tvc_protocol::encoding::{
    canonicalize_json_str, canonicalize_json_value, encode_decimal_u64, encode_lower_hex,
    jcs_serialize,
};
use zolana_tvc_protocol::error::{ErrorCode, TvcError};
use zolana_tvc_protocol::release::{
    sign_release_policy, verify_signed_release_policy, PinnedReleaseAuthorities,
    ReleaseAuthorityKey,
};
use zolana_tvc_protocol::types::{
    ClientAuthorization, ClientGrant, HealthResponse, HealthStatus, Network, Operation,
    OperationKind, OperationRequest, ReleaseAuthoritySignature, ReleasePolicy, ServiceInfo,
    SignedReleasePolicy, WalletDescriptor, WalletGrant,
};

const OPERATIONS: [OperationKind; 5] = [
    OperationKind::Bootstrap,
    OperationKind::Decrypt,
    OperationKind::Derive,
    OperationKind::TransactionKeys,
    OperationKind::Prove,
];

const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

fn sha256_label(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// A signature over SHA-256(digest) must not pass as a signature over `digest`;
/// the TypeScript client checks the same fixture.
pub fn reject_double_hashed_signature(
    public_sec1: &[u8],
    digest: &[u8; 32],
    double_hashed_signature: &[u8],
) -> Result<(), TvcError> {
    match verify_p256_prehash(public_sec1, digest, double_hashed_signature) {
        Ok(()) => Err(TvcError::new(ErrorCode::DoubleHashRejected)),
        Err(error) if error.code == ErrorCode::InvalidSignature => Ok(()),
        Err(error) => Err(error),
    }
}

/// What the TypeScript client accepts as a Turnkey App Proof: a documented
/// proof type, signed over the exact UTF-8 payload in either S half.
fn verify_turnkey_app_proof(
    proof_payload_utf8: &str,
    qos_public_key: &[u8],
    signature: &[u8],
) -> Result<(), TvcError> {
    let payload: Value = serde_json::from_str(proof_payload_utf8)
        .map_err(|_| TvcError::new(ErrorCode::TurnkeyEvidenceInvalid))?;
    match payload.get("type").and_then(Value::as_str) {
        Some("APP_PROOF_TYPE_POLICY_OUTCOME" | "APP_PROOF_TYPE_ADDRESS_DERIVATION") => {}
        _ => return Err(TvcError::new(ErrorCode::UnsupportedProofPath)),
    }
    let public = QosP256Public::from_bytes(qos_public_key)?;
    verify_turnkey_app_proof_p256_message(&public.signing, proof_payload_utf8.as_bytes(), signature)
        .map_err(|_| TvcError::new(ErrorCode::TurnkeyEvidenceInvalid))
}

/// What `discovery-binding.json` expects: check for check, the TypeScript
/// client's `bindDiscoveryToPolicy`. The policy has already verified for the
/// client's network, so discovery must name that network too.
pub fn bind_discovery_to_policy(
    info: &ServiceInfo,
    policy: &ReleasePolicy,
) -> Result<(), TvcError> {
    if info.network != policy.network {
        return Err(TvcError::new(ErrorCode::NetworkMismatch));
    }
    if info.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if info.proof_type != TVC_APP_PROOF_TYPE {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.release_id != policy.release_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.security_domain_id != policy.security_domain_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.quorum_key_id != policy.quorum_key_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.quorum_key_epoch != policy.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    if info.quorum_public_key != policy.quorum_public_key {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    let manifest = encode_lower_hex(&info.manifest_digest);
    if !policy
        .accepted_manifest_digests
        .iter()
        .any(|value| value == &manifest)
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    let executable = encode_lower_hex(&info.executable_digest);
    if !policy
        .accepted_executable_digests
        .iter()
        .any(|value| value == &executable)
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.supported_operations != policy.allowed_operations {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.max_encrypted_request_bytes != u64::from(policy.max_encrypted_request_bytes)
        || info.max_encrypted_response_bytes != u64::from(policy.max_encrypted_response_bytes)
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    Ok(())
}

fn sub_mod_n(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let n = P256_N[i] as u16;
        let v = s[i] as u16;
        let sub = n.wrapping_sub(v).wrapping_sub(borrow);
        out[i] = sub as u8;
        borrow = if n < v + borrow { 1 } else { 0 };
    }
    out
}

fn high_s_signature(low_s: &[u8; 64]) -> [u8; 64] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&low_s[32..]);
    let high = sub_mod_n(&s);
    let mut out = *low_s;
    out[32..].copy_from_slice(&high);
    out
}

fn der_encode_signature(raw: &[u8; 64]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend_from_slice(&v);
        out
    }
    let r = integer(&raw[..32]);
    let s = integer(&raw[32..]);
    let mut seq = r;
    seq.extend_from_slice(&s);
    let mut out = vec![0x30, seq.len() as u8];
    out.extend_from_slice(&seq);
    out
}

fn sample_descriptor(client_public: &[u8], security_domain: [u8; 32]) -> WalletDescriptor {
    WalletDescriptor {
        version: API_VERSION,
        security_domain_id: security_domain,
        network: Network::Devnet,
        turnkey_organization_id: "child-org".to_owned(),
        turnkey_wallet_id: "turnkey-wallet".to_owned(),
        address: "4E2agEUkMiuP3ABYbYTYXuU7bYyqPb3uGsLqs7RDd1U5".to_owned(),
        allowed_clients: vec![ClientGrant {
            client_public_key: client_public.to_vec(),
            allowed_operations: OPERATIONS.to_vec(),
        }],
        provisioning_signature: vec![0u8; 64],
    }
}

/// The release a sample request is bound to.
struct Running {
    release_id: String,
    manifest_digest: [u8; 32],
    executable_digest: [u8; 32],
    security_domain_id: [u8; 32],
    quorum_key_id: String,
    quorum_key_epoch: u64,
}

fn sample_request(client_public: &[u8], running: &Running) -> OperationRequest {
    OperationRequest {
        version: API_VERSION,
        request_id: sha256_label("zolana-tvc-test-request-id"),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_300_000,
        target_release_id: running.release_id.clone(),
        target_manifest_digest: running.manifest_digest,
        target_executable_digest: running.executable_digest,
        quorum_key_id: running.quorum_key_id.clone(),
        quorum_key_epoch: running.quorum_key_epoch,
        wallet_descriptor: sample_descriptor(client_public, running.security_domain_id),
        sealed_seed: None,
        client_response_public_key: client_public.to_vec(),
        operation: Operation::Bootstrap,
        authorization: ClientAuthorization {
            client_key_id: "client-1".to_owned(),
            signature: Vec::new(),
        },
    }
}

fn sample_running() -> Running {
    Running {
        release_id: "tvc-dev-phase0".to_owned(),
        manifest_digest: sha256_label("zolana-tvc-test-manifest"),
        executable_digest: sha256_label("zolana-tvc-test-executable"),
        security_domain_id: sha256_label("zolana-tvc-test-security-domain"),
        quorum_key_id: "quorum-dev-1".to_owned(),
        quorum_key_epoch: 1,
    }
}

fn sample_info(quorum: &QosP256Public, ephemeral: &QosP256Public) -> ServiceInfo {
    let running = sample_running();
    ServiceInfo {
        version: API_VERSION,
        network: Network::Devnet,
        security_domain_id: running.security_domain_id,
        release_id: running.release_id,
        manifest_digest: running.manifest_digest,
        executable_digest: running.executable_digest,
        quorum_public_key: quorum.to_bytes().to_vec(),
        quorum_key_id: running.quorum_key_id,
        quorum_key_epoch: running.quorum_key_epoch,
        ephemeral_public_key: ephemeral.to_bytes().to_vec(),
        supported_operations: OPERATIONS.to_vec(),
        max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
    }
}

fn sample_policy(info: &ServiceInfo) -> ReleasePolicy {
    ReleasePolicy {
        version: API_VERSION,
        release_id: info.release_id.clone(),
        network: info.network,
        tvc_application_id: "zolana-tvc-privacy-wallet".to_owned(),
        security_domain_id: info.security_domain_id,
        accepted_manifest_digests: vec![encode_lower_hex(&info.manifest_digest)],
        accepted_executable_digests: vec![encode_lower_hex(&info.executable_digest)],
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        quorum_public_key: info.quorum_public_key.clone(),
        allowed_operations: info.supported_operations.clone(),
        max_encrypted_request_bytes: u32::try_from(info.max_encrypted_request_bytes).expect("u32"),
        max_encrypted_response_bytes: u32::try_from(info.max_encrypted_response_bytes)
            .expect("u32"),
        turnkey_trust_root_id: EXPECTED_TURNKEY_TRUST_ROOT_ID.to_owned(),
        turnkey_proof_schema_versions: vec!["turnkey.boot_proof.v1".to_owned()],
        valid_from_ms: 1_700_000_000_000,
        expires_at_ms: 1_800_000_000_000,
        revocation_epoch: 0,
    }
}

fn authority_public(secret: &[u8; 32]) -> Vec<u8> {
    public_key_uncompressed(
        &SecretKey::from_slice(secret)
            .expect("authority scalar")
            .public_key(),
    )
    .to_vec()
}

/// Build the committed fixture set. File bodies are compact JSON objects.
pub fn fixture_files() -> Result<BTreeMap<String, String>, zolana_tvc_protocol::error::TvcError> {
    let client_sk = sha256_label("zolana-tvc-test-client-sk");
    let encryption_sk = sha256_label("zolana-tvc-test-encryption-sk");
    let signing_sk = sha256_label("zolana-tvc-test-signing-sk");
    let ephemeral_sk = sha256_label("zolana-tvc-test-ephemeral-sk");
    let wrong_sk = sha256_label("zolana-tvc-test-wrong-sk");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sha256_label("zolana-tvc-test-nonce")[..12]);

    let client_public = public_key_uncompressed(
        &SecretKey::from_slice(&client_sk)
            .expect("test client scalar")
            .public_key(),
    );
    let quorum = qos_public_from_secrets(&encryption_sk, &signing_sk)?;
    let ephemeral = qos_public_from_secrets(&ephemeral_sk, &signing_sk)?;
    let running = sample_running();
    let request =
        authorize_operation_request(sample_request(&client_public, &running), &client_sk)?;
    let request_digest_bytes = request_digest(&request)?;
    let client_auth_text = client_auth_message(&request_digest_bytes);
    let client_auth = client_auth_digest(&request_digest_bytes);
    verify_client_authorization(&request, &client_public).expect("signed request verifies");

    let plaintext = b"qos-envelope-plaintext";
    let envelope = qos_encrypt_with(&quorum.encryption, plaintext, &ephemeral_sk, &nonce)?;
    let decrypted = qos_decrypt(&encryption_sk, &envelope)?;
    assert_eq!(decrypted.as_slice(), plaintext);

    let mut files = BTreeMap::new();

    let jcs_input = json!({"b": 1, "a": {"d": true, "c": "z"}, "arr": [2, 1]});
    let jcs = canonicalize_json_value(&jcs_input)?;
    files.insert(
        "jcs-object-sort.json".to_owned(),
        fixture_json(&json!({
            "id": "jcs-object-sort",
            "input": jcs_input,
            "canonical_json": jcs,
            "canonical_sha256": encode_lower_hex(&Sha256::digest(jcs.as_bytes())),
        })),
    );

    files.insert(
        "canonical-u64.json".to_owned(),
        fixture_json(&json!({
            "id": "canonical-u64",
            "values": [
                {"input": encode_decimal_u64(0), "encoded": encode_decimal_u64(0)},
                {"input": encode_decimal_u64(1), "encoded": encode_decimal_u64(1)},
                {"input": encode_decimal_u64(1_700_000_000_000), "encoded": encode_decimal_u64(1_700_000_000_000)},
                {"input": encode_decimal_u64(u64::MAX), "encoded": encode_decimal_u64(u64::MAX)},
            ],
            "negative": ["01", "+1", "1.0", "0x1", ""],
        }))
        ,
    );

    files.insert(
        "request-digest.json".to_owned(),
        fixture_json(&json!({
            "id": "request-digest",
            "request": serde_json::to_value(&request).expect("request"),
            "request_digest": encode_lower_hex(&request_digest_bytes),
            "client_auth_message": client_auth_text,
            "client_auth_digest": encode_lower_hex(&client_auth),
            "includes_client_key_id": true,
            "excludes_signature_only": true,
        })),
    );

    let mut mutated_key = request.clone();
    mutated_key.authorization.client_key_id = "client-2".to_owned();
    files.insert(
        "authorization-mutation.json".to_owned(),
        fixture_json(&json!({
            "id": "authorization-mutation",
            "original_digest": encode_lower_hex(&request_digest_bytes),
            "mutated_client_key_id_digest": encode_lower_hex(&request_digest(&mutated_key)?),
            "mutated_client_key_id_verifies": verify_client_authorization(&mutated_key, &client_public).is_ok(),
        }))
        ,
    );

    let raw_sig = sign_p256_prehash(&client_sk, &client_auth)?;
    verify_p256_prehash(&client_public, &client_auth, &raw_sig).expect("raw sig");
    let der = der_encode_signature(&raw_sig);
    let high = high_s_signature(&raw_sig);
    let compressed = SecretKey::from_slice(&client_sk)
        .expect("client")
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let double_hash: [u8; 32] = Sha256::digest(client_auth).into();
    let double_sig = sign_p256_prehash(&client_sk, &double_hash)?;

    files.insert(
        "p256-signatures.json".to_owned(),
        fixture_json(&json!({
            "id": "p256-signatures",
            "public_key": encode_lower_hex(&client_public),
            "digest": encode_lower_hex(&client_auth),
            "raw_low_s": encode_lower_hex(&raw_sig),
            "der": encode_lower_hex(&der),
            "high_s": encode_lower_hex(&high),
            "compressed_public_key": encode_lower_hex(&compressed),
            "double_hash_digest": encode_lower_hex(&double_hash),
            "double_hash_signature": encode_lower_hex(&double_sig),
            "message": client_auth_text,
        })),
    );

    files.insert(
        "qos-p256-public.json".to_owned(),
        fixture_json(&json!({
            "id": "qos-p256-public",
            "public_key": encode_lower_hex(&quorum.to_bytes()),
            "length": QOS_P256_PUBLIC_LEN,
            "encryption_sec1": encode_lower_hex(&quorum.encryption),
            "signing_sec1": encode_lower_hex(&quorum.signing),
        })),
    );

    files.insert(
        "qos-borsh-envelope.json".to_owned(),
        fixture_json(&json!({
            "id": "qos-borsh-envelope",
            "receiver_encryption_public": encode_lower_hex(&quorum.encryption),
            "ephemeral_secret": encode_lower_hex(&ephemeral_sk),
            "nonce": encode_lower_hex(&nonce),
            "plaintext": encode_lower_hex(plaintext),
            "envelope": encode_lower_hex(&envelope),
        })),
    );

    let mut truncated = envelope.clone();
    truncated.truncate(envelope.len().saturating_sub(8));
    let _wrong_plain = qos_decrypt(&wrong_sk, &envelope);
    files.insert(
        "qos-negative.json".to_owned(),
        fixture_json(&json!({
            "id": "qos-negative",
            "truncated_envelope": encode_lower_hex(&truncated),
            "wrong_receiver_secret": encode_lower_hex(&wrong_sk),
            "envelope": encode_lower_hex(&envelope),
        })),
    );

    files.insert(
        "json-reject.json".to_owned(),
        fixture_json(&json!({
            "id": "json-reject",
            "unknown_field": "{\"status\":\"Healthy\",\"extra\":true}",
            "duplicate_field": "{\"status\":\"Healthy\",\"status\":\"Healthy\"}",
        })),
    );

    let proof_payload = canonicalize_json_str(
        r#"{"outcome":"Completed","type":"APP_PROOF_TYPE_POLICY_OUTCOME","version":1}"#,
    )?;
    let proof_sig =
        zolana_tvc_protocol::crypto::sign_p256_message(&signing_sk, proof_payload.as_bytes())?;
    let parsed_proof_sig = p256::ecdsa::Signature::from_slice(&proof_sig).expect("signature");
    let (proof_r, proof_s) = parsed_proof_sig.split_scalars();
    let high_s_sig: [u8; 64] = p256::ecdsa::Signature::from_scalars(*proof_r, -*proof_s)
        .expect("high-s signature")
        .to_bytes()
        .into();
    let non_jcs_payload = r#"{"type":"APP_PROOF_TYPE_POLICY_OUTCOME","timestampMs":"1750000000000","policyOutcome":{}}"#;
    let non_jcs_sig =
        zolana_tvc_protocol::crypto::sign_p256_message(&signing_sk, non_jcs_payload.as_bytes())?;
    files.insert(
        "proof-payload-utf8.json".to_owned(),
        fixture_json(&json!({
            "id": "proof-payload-utf8",
            "proof_payload": proof_payload,
            "proof_payload_hex": encode_lower_hex(proof_payload.as_bytes()),
            "public_key": encode_lower_hex(&quorum.to_bytes()),
            "signature": encode_lower_hex(&proof_sig),
            "high_s_signature": encode_lower_hex(&high_s_sig),
            "non_jcs_payload": non_jcs_payload,
            "non_jcs_signature": encode_lower_hex(&non_jcs_sig),
        })),
    );

    // What the enclave answers to `GET /health` and `GET /v1/info`.
    let info = sample_info(&quorum, &ephemeral);
    let health = jcs_serialize(&HealthResponse {
        status: HealthStatus::Healthy,
    })?;
    files.insert(
        "http-skeleton.json".to_owned(),
        fixture_json(&json!({
            "id": "http-skeleton",
            "health_status": 200,
            "health_body": health,
            "info_status": 200,
            "info_body": jcs_serialize(&info)?,
            "health_has_release_id": health.contains("tvc-dev-phase0"),
        })),
    );

    files.insert(
        "digests.json".to_owned(),
        fixture_json(&json!({
            "id": "digests",
            "wallet_id_hash": encode_lower_hex(&wallet_id_hash("wallet-phase0-1")),
            "request_id_hash": encode_lower_hex(&request_id_hash(&request.request_id)),
            "result_digest": encode_lower_hex(&result_digest(b"encrypted-result")),
            "sealed_seed_digest": encode_lower_hex(&sealed_seed_digest(b"sealed-seed-bytes")),
        })),
    );

    for (payload, signature) in [
        (proof_payload.as_str(), proof_sig.as_slice()),
        (proof_payload.as_str(), high_s_sig.as_slice()),
        (non_jcs_payload, non_jcs_sig.as_slice()),
    ] {
        verify_turnkey_app_proof(payload, &quorum.to_bytes(), signature)?;
    }
    reject_double_hashed_signature(&client_public, &client_auth, &double_sig)?;

    let authority_sk1 = sha256_label("zolana-tvc-test-release-authority-1");
    let authority_sk2 = sha256_label("zolana-tvc-test-release-authority-2");
    let authority_sk3 = sha256_label("zolana-tvc-test-release-authority-3");
    let policy = sample_policy(&info);
    let authorities = PinnedReleaseAuthorities {
        authority_set_id: "dev-release-1".to_owned(),
        threshold: 1,
        minimum_revocation_epoch: 0,
        keys: vec![
            ReleaseAuthorityKey {
                key_id: "release-1".to_owned(),
                public_key: authority_public(&authority_sk1),
            },
            ReleaseAuthorityKey {
                key_id: "release-2".to_owned(),
                public_key: authority_public(&authority_sk2),
            },
            ReleaseAuthorityKey {
                key_id: "release-3".to_owned(),
                public_key: authority_public(&authority_sk3),
            },
        ],
    };
    let signature = sign_release_policy(&policy, &authority_sk1)?;
    let signed = SignedReleasePolicy {
        policy: policy.clone(),
        authority_set_id: authorities.authority_set_id.clone(),
        signatures: vec![ReleaseAuthoritySignature {
            key_id: "release-1".to_owned(),
            signature: signature.to_vec(),
        }],
    };
    let verify =
        |signed: &SignedReleasePolicy, authorities: &PinnedReleaseAuthorities, network, now| {
            verify_signed_release_policy(signed, authorities, network, now)
                .expect_err("the case is refused")
                .code
                .as_str()
        };
    verify_signed_release_policy(&signed, &authorities, Network::Devnet, 1_750_000_000_000)
        .expect("signed policy");
    let mut unsigned = signed.clone();
    unsigned.signatures.clear();
    let mut duplicate = signed.clone();
    duplicate.signatures.push(signed.signatures[0].clone());
    let mut unknown = signed.clone();
    unknown.signatures[0].key_id = "release-unknown".to_owned();
    let mut mutated = signed.clone();
    mutated.policy.release_id = "other-release".to_owned();
    let zero_threshold = PinnedReleaseAuthorities {
        threshold: 0,
        ..authorities.clone()
    };
    let mut wrong_trust_root = signed.clone();
    wrong_trust_root.policy.turnkey_trust_root_id = "other-root".to_owned();
    let revoking_authorities = PinnedReleaseAuthorities {
        minimum_revocation_epoch: 1,
        ..authorities.clone()
    };
    files.insert(
        "signed-release-policy.json".to_owned(),
        fixture_json(&json!({
            "id": "signed-release-policy",
            "now_ms": "1750000000000",
            "network": Network::Devnet,
            "authorities": authorities,
            "signed": signed,
            "policy_digest": encode_lower_hex(&zolana_tvc_protocol::release::policy_signing_digest(&policy)?),
            "empty_signatures": verify(&unsigned, &authorities, Network::Devnet, 1_750_000_000_000),
            "empty_signatures_input": unsigned,
            "duplicate_key_id": verify(&duplicate, &authorities, Network::Devnet, 1_750_000_000_000),
            "duplicate_key_id_input": duplicate,
            "unknown_key_id": verify(&unknown, &authorities, Network::Devnet, 1_750_000_000_000),
            "unknown_key_id_input": unknown,
            "mutated_policy": verify(&mutated, &authorities, Network::Devnet, 1_750_000_000_000),
            "mutated_policy_input": mutated,
            "zero_threshold": verify(&signed, &zero_threshold, Network::Devnet, 1_750_000_000_000),
            "zero_threshold_authorities": zero_threshold,
            "expired": verify(&signed, &authorities, Network::Devnet, 1_900_000_000_000),
            "expired_now_ms": "1900000000000",
            "wrong_trust_root": verify(&wrong_trust_root, &authorities, Network::Devnet, 1_750_000_000_000),
            "wrong_trust_root_input": wrong_trust_root,
            "revoked_epoch": verify(&signed, &revoking_authorities, Network::Devnet, 1_750_000_000_000),
            "revoked_epoch_authorities": revoking_authorities,
            "wrong_network": verify(&signed, &authorities, Network::Mainnet, 1_750_000_000_000),
            "wrong_network_expected": Network::Mainnet,
        }))
        ,
    );

    bind_discovery_to_policy(&info, &policy)?;
    let mut binding_cases: Vec<(&str, ServiceInfo)> = Vec::new();
    {
        let mut m = info.clone();
        m.network = Network::Mainnet;
        binding_cases.push(("network", m));
    }
    {
        let mut m = info.clone();
        m.version = API_VERSION + 1;
        binding_cases.push(("version", m));
    }
    {
        let mut m = info.clone();
        m.proof_type = "zolana.tvc.other.v1".to_owned();
        binding_cases.push(("proof_type", m));
    }
    {
        let mut m = info.clone();
        m.release_id = "other-release".to_owned();
        binding_cases.push(("release_id", m));
    }
    {
        let mut m = info.clone();
        m.security_domain_id = [0xaa; 32];
        binding_cases.push(("security_domain_id", m));
    }
    {
        let mut m = info.clone();
        m.quorum_key_id = "other-quorum".to_owned();
        binding_cases.push(("quorum_key_id", m));
    }
    {
        let mut m = info.clone();
        m.quorum_key_epoch = 2;
        binding_cases.push(("quorum_key_epoch", m));
    }
    {
        let mut m = info.clone();
        m.quorum_public_key = info.ephemeral_public_key.clone();
        binding_cases.push(("quorum_public_key", m));
    }
    {
        let mut m = info.clone();
        m.manifest_digest = [0xcc; 32];
        binding_cases.push(("manifest_digest", m));
    }
    {
        let mut m = info.clone();
        m.executable_digest = [0xdd; 32];
        binding_cases.push(("executable_digest", m));
    }
    {
        let mut m = info.clone();
        m.supported_operations.pop();
        binding_cases.push(("operations_truncated", m));
    }
    {
        let mut m = info.clone();
        m.supported_operations.swap(0, 1);
        binding_cases.push(("operations_reordered", m));
    }
    {
        let mut m = info.clone();
        m.max_encrypted_request_bytes += 1;
        binding_cases.push(("max_encrypted_request_bytes", m));
    }
    {
        let mut m = info.clone();
        m.max_encrypted_response_bytes += 1;
        binding_cases.push(("max_encrypted_response_bytes", m));
    }
    let binding_cases: Vec<Value> = binding_cases
        .into_iter()
        .map(|(name, mutated)| {
            let error = bind_discovery_to_policy(&mutated, &policy)
                .expect_err("binding case")
                .code
                .as_str();
            json!({ "name": name, "info": mutated, "error": error })
        })
        .collect();
    files.insert(
        "discovery-binding.json".to_owned(),
        fixture_json(&json!({
            "id": "discovery-binding",
            "policy": policy,
            "info": info,
            "cases": binding_cases,
        })),
    );

    let descriptor = sample_descriptor(&client_public, sample_running().security_domain_id);
    let descriptor_digest = descriptor_digest(&descriptor)?;
    files.insert(
        "descriptor-digest.json".to_owned(),
        fixture_json(&json!({
            "id": "descriptor-digest",
            "descriptor": descriptor,
            "descriptor_digest": encode_lower_hex(&descriptor_digest),
        })),
    );

    let grant = WalletGrant {
        version: API_VERSION,
        descriptor_digest,
        client_key_id: "tvc-browser-p256-00112233445566778899aabbccddeeff".to_owned(),
        project_id: "project-1".to_owned(),
        issued_at_ms: 1_800_000_000_000,
        expires_at_ms: 1_800_000_900_000,
        signature: vec![0u8; 64],
    };
    files.insert(
        "wallet-grant-digest.json".to_owned(),
        fixture_json(&json!({
            "id": "wallet-grant-digest",
            "grant": grant,
            "grant_digest": encode_lower_hex(&wallet_grant_digest(&grant)?),
        })),
    );

    Ok(files)
}

/// A fixture body as canonical JSON, so its bytes do not depend on whether a
/// linked crate turns on `serde_json/preserve_order`.
fn fixture_json(value: &Value) -> String {
    canonicalize_json_value(value).expect("fixture json")
}

pub fn manifest_for(files: &BTreeMap<String, String>) -> Value {
    let mut entries = serde_json::Map::new();
    for (name, body) in files {
        entries.insert(
            name.clone(),
            json!(encode_lower_hex(&Sha256::digest(body.as_bytes()))),
        );
    }
    json!({
        "algorithm": "sha256",
        "files": Value::Object(entries),
    })
}

pub fn write_fixtures(dir: &Path) -> Result<(), zolana_tvc_protocol::error::TvcError> {
    std::fs::create_dir_all(dir).expect("create fixtures dir");
    let files = fixture_files()?;
    let manifest = serde_json::to_string_pretty(&manifest_for(&files)).expect("manifest");
    for (name, body) in &files {
        std::fs::write(dir.join(name), body.as_bytes()).expect("write fixture");
    }
    std::fs::write(dir.join("MANIFEST.json"), manifest.as_bytes()).expect("write manifest");
    Ok(())
}

pub fn verify_fixtures(dir: &Path) -> Result<(), zolana_tvc_protocol::error::TvcError> {
    let files = fixture_files()?;
    let committed_manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("MANIFEST.json")).expect("read manifest"))
            .expect("parse manifest");
    let expected_manifest = manifest_for(&files);
    assert_eq!(
        committed_manifest, expected_manifest,
        "fixture manifest mismatch"
    );
    for (name, body) in files {
        let committed = std::fs::read_to_string(dir.join(&name)).expect("read fixture");
        assert_eq!(committed, body, "fixture {name} mismatch");
    }
    Ok(())
}
