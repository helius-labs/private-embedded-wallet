//! Proving: the one place the nullifier secret is consumed rather than derived
//! from. The client assembles the whole prover request, with `null` in every
//! nullifier secret slot that is this wallet's to fill; the enclave fills those
//! slots, changes nothing else, and seals the request to a prover whose
//! attestation passes the network's signed prover policy. The client posts the
//! sealed request; only the attested prover can open it.
//!
//! Ownership of the inputs is not checked: a slot filled for a UTXO this wallet
//! does not own yields a witness the circuit rejects, and a proof reveals
//! nothing about the secret either way.

use serde_json::{Map, Value};
use spr_prover_tee::{
    verify_with, Anchors, Attestation, EncryptedRequest, PolicySigners, SignedPolicyFile,
    MAX_SIGNED_POLICY_BYTES,
};
use spr_tvc_protocol::constants::{MAX_PROVER_TARGET_LEN, MAX_PROVE_INPUTS};
use spr_tvc_protocol::types::{FailureStage, ProverSealing, SealedProverRequest};
use zeroize::{Zeroize, Zeroizing};

use super::Failure;
use crate::network::NET;

/// A proving key's route, `<prefix>/prove/<key>`; `<key>` is the key file name
/// without `.key`.
const PROVE_PATH: &str = "/prove/";

/// The provers a `Prove` may seal to.
pub(crate) struct ProverTrust {
    /// Who signs the policy files a sealing may present.
    pub signers: PolicySigners,
    /// The vendor roots a prover's evidence must chain to.
    pub anchors: Anchors,
}

impl ProverTrust {
    /// The trust the enclave image carries: the production vendor roots, under
    /// the signers of the network the image was built for.
    pub(crate) fn image() -> Self {
        Self {
            signers: PolicySigners::new(
                spr_tvc_enclave::NETWORK.as_str(),
                NET.policy_signers.to_vec(),
                NET.policy_threshold,
            )
            .expect("policy signers are well formed"),
            anchors: Anchors::PRODUCTION,
        }
    }
}

/// A prover policy file as a network publishes it: `policy`, released by
/// `signer` for `network` until `expires_at`, and a freshness part covering
/// `fresh_from..expires_at`, signed by a key the release names.
#[cfg(any(test, feature = "local-dev"))]
pub(crate) fn sign_policy(
    signer: &ed25519_dalek::SigningKey,
    network: &str,
    policy: spr_prover_tee::TeePolicy,
    fresh_from: u64,
    expires_at: u64,
) -> SignedPolicyFile {
    use spr_prover_tee::{FreshnessSigners, ReleasePayload};

    // The freshness key, distinct from the release signer.
    let mut seed = signer.to_bytes();
    seed[0] ^= 0xff;
    let freshness = ed25519_dalek::SigningKey::from_bytes(&seed);
    let release = ReleasePayload {
        network: network.to_owned(),
        version: 1,
        expires_at,
        freshness: FreshnessSigners::of(std::slice::from_ref(&freshness), expires_at - fresh_from),
        policy,
    };
    SignedPolicyFile::sign(
        &release,
        std::slice::from_ref(signer),
        (fresh_from, expires_at),
        std::slice::from_ref(&freshness),
    )
    .expect("policy file")
}

/// Writes `secret` as the prover's field encoding: the big-endian integer in
/// lowercase hex without leading zeros, as the Zolana SDK writes every field.
fn field_hex(secret: &[u8]) -> String {
    let hex = hex::encode(secret);
    let digits = hex.trim_start_matches('0');
    format!("0x{}", if digits.is_empty() { "0" } else { digits })
}

fn fill(slot: &mut Value, secret: &str, filled: &mut usize) -> Result<(), Failure> {
    match slot {
        Value::Null => {
            *slot = Value::String(secret.to_owned());
            *filled += 1;
            Ok(())
        }
        Value::String(_) => Ok(()),
        _ => Err(Failure::Invalid),
    }
}

fn object(value: &mut Value) -> Result<&mut Map<String, Value>, Failure> {
    value.as_object_mut().ok_or(Failure::Invalid)
}

/// The request with this wallet's secret in every open slot. Refuses a body
/// that names an unknown circuit, that has no slot to fill, or that asks for
/// the secret in a padding slot.
pub(super) fn complete(request: &Value, nullifier_secret: &[u8]) -> Result<Value, Failure> {
    let mut request = request.clone();
    let body = object(&mut request)?;
    let circuit = body
        .get("circuitType")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?
        .to_owned();
    let secret = Zeroizing::new(field_hex(nullifier_secret));
    let mut filled = 0;
    match circuit.as_str() {
        "transfer-confidential" | "transfer-ring" => {
            let inputs = body
                .get_mut("inputs")
                .and_then(Value::as_array_mut)
                .ok_or(Failure::Invalid)?;
            if inputs.is_empty() || inputs.len() > MAX_PROVE_INPUTS {
                return Err(Failure::Invalid);
            }
            for input in inputs {
                let input = object(input)?;
                let dummy = input
                    .get("isDummy")
                    .and_then(Value::as_str)
                    .ok_or(Failure::Invalid)?
                    != "0x0";
                let slot = input.get_mut("nullifierSecret").ok_or(Failure::Invalid)?;
                if dummy && slot.is_null() {
                    return Err(Failure::Invalid);
                }
                fill(slot, &secret, &mut filled)?;
            }
        }
        "merge" | "merge-ring" => {
            let inputs = body
                .get("inputs")
                .and_then(Value::as_array)
                .ok_or(Failure::Invalid)?;
            if inputs.is_empty() || inputs.len() > MAX_PROVE_INPUTS {
                return Err(Failure::Invalid);
            }
            let slot = body
                .get_mut("userNullifierSecret")
                .ok_or(Failure::Invalid)?;
            fill(slot, &secret, &mut filled)?;
        }
        _ => return Err(Failure::Invalid),
    }
    if filled == 0 {
        return Err(Failure::Invalid);
    }
    Ok(request)
}

fn slot_count(body: &Map<String, Value>, field: &str) -> Result<usize, Failure> {
    let slots = body
        .get(field)
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    if slots.is_empty() || slots.len() > MAX_PROVE_INPUTS {
        return Err(Failure::Invalid);
    }
    Ok(slots.len())
}

/// The proving key file name, without `.key`, that proves `request`: the
/// circuit family and its slot counts, as the Zolana SDK names its keys.
pub(super) fn proving_key(request: &Value) -> Result<String, Failure> {
    let body = request.as_object().ok_or(Failure::Invalid)?;
    let circuit = body
        .get("circuitType")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let family = match circuit {
        "transfer-confidential" => "transfer_confidential",
        "transfer-ring" => "transfer_ring",
        "merge" => "merge",
        "merge-ring" => "merge_ring",
        _ => return Err(Failure::Invalid),
    };
    let inputs = slot_count(body, "inputs")?;
    let outputs = if circuit.starts_with("merge") {
        1
    } else {
        slot_count(body, "outputs")?
    };
    Ok(format!("{family}_{inputs}_{outputs}"))
}

/// Seals the completed request to the prover `sealing` attests. A refused
/// policy or attestation is the `Prover` stage, so the client can attest
/// again; a malformed request or target is refused outright.
pub(super) fn seal(
    request: &Value,
    nullifier_secret: &[u8],
    sealing: &ProverSealing,
    trust: &ProverTrust,
    now_ms: u64,
) -> Result<SealedProverRequest, Failure> {
    check_target(&sealing.target, &proving_key(request)?)?;
    let prover_key = attested_key(sealing, trust, now_ms)?;
    let mut complete = complete(request, nullifier_secret)?;
    let plaintext = serde_json::to_vec(&complete).map(Zeroizing::new);
    scrub(&mut complete);
    let plaintext = plaintext.map_err(|_| Failure::Unavailable)?;
    let sealed = EncryptedRequest::encrypt(&prover_key, "POST", &sealing.target, &plaintext)
        .map_err(|_| Failure::Unavailable)?;
    let enc = hex::decode(&sealed.enc)
        .ok()
        .and_then(|enc| <[u8; 32]>::try_from(enc).ok())
        .ok_or(Failure::Unavailable)?;
    Ok(SealedProverRequest {
        target: sealing.target.clone(),
        enc,
        ciphertext: sealed.body.clone(),
        response_key: *sealed.response_key(),
    })
}

/// The HPKE key of a prover whose attestation, for the client's nonce,
/// passes a current policy enough of the network's signers signed.
///
/// The enclave keeps no state, so it cannot refuse a file older than one it
/// accepted before; the earlier of the release and freshness expiries bounds
/// how long a superseded policy stays usable.
fn attested_key(
    sealing: &ProverSealing,
    trust: &ProverTrust,
    now_ms: u64,
) -> Result<[u8; 32], Failure> {
    let refused = || Failure::Stage(FailureStage::Prover);
    let file = serde_json::to_vec(&sealing.policy).map_err(|_| refused())?;
    if file.len() > MAX_SIGNED_POLICY_BYTES {
        return Err(refused());
    }
    let verified =
        SignedPolicyFile::verify(&file, &trust.signers, now_ms / 1_000).map_err(|_| refused())?;
    let policy = verified.release.policy;
    let attestation: Attestation =
        serde_json::from_value(sealing.attestation.clone()).map_err(|_| refused())?;
    verify_with(
        attestation,
        &policy,
        &sealing.nonce,
        now_ms / 1_000,
        &trust.anchors,
    )
    .map(|prover| prover.hpke_public_key)
    .map_err(|_| refused())
}

/// `target` must be `key`'s route, `/prove/<key>`, with no prefix or query:
/// the encryption binds the route, which a gateway serves under any path.
fn check_target(target: &str, key: &str) -> Result<(), Failure> {
    if target.len() > MAX_PROVER_TARGET_LEN || target.strip_prefix(PROVE_PATH) != Some(key) {
        return Err(Failure::Invalid);
    }
    Ok(())
}

/// Wipes every nullifier secret slot of a completed request.
fn scrub(request: &mut Value) {
    let wipe = |slot: Option<&mut Value>| {
        if let Some(Value::String(secret)) = slot {
            secret.zeroize();
        }
    };
    wipe(request.get_mut("userNullifierSecret"));
    if let Some(inputs) = request.get_mut("inputs").and_then(Value::as_array_mut) {
        for input in inputs {
            wipe(input.get_mut("nullifierSecret"));
        }
    }
}
