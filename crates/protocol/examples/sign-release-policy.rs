//! Sign one release policy with a one-time authority key.
//!
//! Usage:
//!
//! ```sh
//! cargo run -p zolana-tvc-protocol --example sign-release-policy \
//!     -- policy.json <authority-set-id>
//! cargo run -p zolana-tvc-protocol --example sign-release-policy \
//!     -- --local-testkit <out-dir>
//! ```
//!
//! `policy.json` is a `ReleasePolicy` in the same camelCase shape the client
//! pins. The output is the two objects a client needs: the signed policy and
//! the pinned authority set.
//!
//! `--local-testkit` signs a policy for the unattested local testkit
//! (`packages/tvc-wallet/src/local-testkit.json`), valid for 30 days, and
//! writes `<out-dir>/release-policy.json` and
//! `<out-dir>/release-authorities.json` for a local gateway. Never deploy it.
//!
//! The signing key is generated here, used once, and never written anywhere.
//! That is the property being bought: a policy cannot be quietly re-signed
//! later, because doing so requires a new authority set, and a new authority
//! set is a change every client must be updated to accept. The private half
//! existing anywhere afterwards would defeat it, so this prints only the
//! public half.
//!
//! Entropy comes from `/dev/urandom` rather than a dependency, so an operator
//! running the ceremony can see exactly where the key came from.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use zeroize::Zeroizing;

use zolana_tvc_protocol::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID};
use zolana_tvc_protocol::crypto::public_key_uncompressed;
use zolana_tvc_protocol::digest::sha256;
use zolana_tvc_protocol::release::{
    sign_release_policy, verify_signed_release_policy, PinnedReleaseAuthorities,
    ReleaseAuthorityKey,
};
use zolana_tvc_protocol::types::{
    ClientAuthorizationScheme, Environment, OperationKind, ReleaseAuthoritySignature,
    ReleasePolicy, SignedReleasePolicy,
};

const LOCAL_TESTKIT: &str = include_str!("../../../packages/tvc-wallet/src/local-testkit.json");
const LOCAL_VALIDITY_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

fn urandom_scalar() -> Result<Zeroizing<[u8; 32]>, String> {
    // A uniformly random 32-byte string is only a valid P-256 scalar when it
    // is in range and non-zero. Rejection keeps the distribution honest; a
    // reduction would not.
    let mut source = fs::File::open("/dev/urandom").map_err(|error| error.to_string())?;
    for _ in 0..64 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        source
            .read_exact(bytes.as_mut())
            .map_err(|error| error.to_string())?;
        if p256::ecdsa::SigningKey::from_slice(bytes.as_ref()).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not draw a valid P-256 scalar".to_owned())
}

/// Signs `policy` with a one-time key and returns it with the authority set
/// that pins that key.
fn sign(
    policy: ReleasePolicy,
    authority_set_id: String,
) -> Result<(SignedReleasePolicy, PinnedReleaseAuthorities), String> {
    let secret = urandom_scalar()?;
    let signing_key =
        p256::ecdsa::SigningKey::from_slice(secret.as_ref()).map_err(|error| error.to_string())?;
    let public = public_key_uncompressed(&p256::PublicKey::from(signing_key.verifying_key()));
    let signature = sign_release_policy(&policy, &secret).map_err(|error| format!("{error:?}"))?;

    let key_id = format!("{}-authority-1", policy.release_id);
    let signed = SignedReleasePolicy {
        policy,
        authority_set_id: authority_set_id.clone(),
        signatures: vec![ReleaseAuthoritySignature {
            key_id: key_id.clone(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: signature.to_vec(),
        }],
    };
    let authorities = PinnedReleaseAuthorities {
        authority_set_id,
        threshold: 1,
        minimum_revocation_epoch: 0,
        keys: vec![ReleaseAuthorityKey {
            key_id,
            public_key: public.to_vec(),
        }],
    };
    // Verify before handing it out. The private half is gone the moment this
    // returns, so an output that does not verify could never be repaired.
    verify_signed_release_policy(&signed, &authorities, signed.policy.valid_from_ms)
        .map_err(|error| format!("signed policy failed its own verification: {error:?}"))?;
    Ok((signed, authorities))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Testkit {
    release_id: String,
    quorum_key_id: String,
    security_domain_label: String,
    manifest_label: String,
    executable_label: String,
    quorum_public_key: String,
    operations: Vec<OperationKind>,
}

/// The local testkit's release, valid from an hour ago for 30 days.
fn local_testkit_policy() -> Result<ReleasePolicy, String> {
    let testkit: Testkit =
        serde_json::from_str(LOCAL_TESTKIT).map_err(|error| error.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    let now = u64::try_from(now).map_err(|error| error.to_string())?;
    Ok(ReleasePolicy {
        version: API_VERSION,
        release_id: testkit.release_id,
        environment: Environment::Development,
        tvc_application_id: "local-testkit".to_owned(),
        security_domain_id: sha256(testkit.security_domain_label.as_bytes()),
        accepted_manifest_digests: vec![hex::encode(sha256(testkit.manifest_label.as_bytes()))],
        accepted_executable_digests: vec![hex::encode(sha256(testkit.executable_label.as_bytes()))],
        quorum_key_id: testkit.quorum_key_id,
        quorum_key_epoch: 1,
        quorum_public_key: hex::decode(testkit.quorum_public_key)
            .map_err(|error| error.to_string())?,
        allowed_operations: testkit.operations,
        max_encrypted_request_bytes: 262_144,
        max_encrypted_response_bytes: 262_144,
        turnkey_trust_root_id: EXPECTED_TURNKEY_TRUST_ROOT_ID.to_owned(),
        turnkey_proof_schema_versions: vec!["turnkey.boot_proof.v1".to_owned()],
        valid_from_ms: now.saturating_sub(60 * 60 * 1_000),
        expires_at_ms: now.saturating_add(LOCAL_VALIDITY_MS),
        revocation_epoch: 0,
    })
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, json).map_err(|error| format!("{}: {error}", path.display()))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, out_dir] if flag == "--local-testkit" => {
            let (signed, authorities) = sign(local_testkit_policy()?, "local-testkit".to_owned())?;
            let out_dir = Path::new(out_dir);
            fs::create_dir_all(out_dir).map_err(|error| error.to_string())?;
            write_json(&out_dir.join("release-policy.json"), &signed)?;
            write_json(&out_dir.join("release-authorities.json"), &authorities)
        }
        [path, authority_set_id, ..] => {
            let policy: ReleasePolicy = serde_json::from_str(
                &fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?,
            )
            .map_err(|error| format!("{path}: {error}"))?;
            let (signed, authorities) = sign(policy, authority_set_id.clone())?;
            let output = serde_json::to_string_pretty(&serde_json::json!({
                "releasePolicy": signed,
                "releaseAuthorities": authorities,
            }))
            .map_err(|error| error.to_string())?;
            println!("{output}");
            Ok(())
        }
        _ => Err(
            "usage: sign-release-policy <policy.json> <authority-set-id>\n       \
             sign-release-policy --local-testkit <out-dir>"
                .to_owned(),
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
