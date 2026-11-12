//! Compile-time-only stand-ins for the local testkit: pinned QOS keys instead
//! of Nitro attestation, an in-process Ed25519 key instead of Turnkey, and
//! either a fixture root and prover policy key for the stand-in prover or the
//! devnet prover trust the enclave image carries. The encrypted operation
//! handlers, sealing, proving, and transaction validation are the real ones.
//! Never linked into the enclave binary.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey};
use qos_p256::P256Pair;
use serde::Deserialize;
use spr_prover_tee::{Anchors, PolicySigners};
use zeroize::Zeroizing;
use zolana_tvc_protocol::digest::sha256;
use zolana_tvc_protocol::encoding::decode_lower_hex_array;
use zolana_tvc_protocol::types::OperationKind;

use crate::custody::{Custody, CustodyError, RawSignature, WalletKey};
use crate::network::NET;
use crate::operations::ProverTrust;
use crate::{AppState, DiscoveryConfig, Runtime, OPERATIONS};

const TESTKIT_JSON: &str = include_str!("../../../packages/tvc-wallet/src/local-testkit.json");
/// The testkit fixture's own format version, which the TypeScript testkit
/// checks too; not the protocol's.
const TESTKIT_VERSION: u8 = 1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Testkit {
    version: u8,
    release_id: String,
    quorum_key_id: String,
    security_domain_label: String,
    manifest_label: String,
    executable_label: String,
    provisioning_private_key_hex: String,
    grant_private_key_hex: String,
    prover_policy_signer_seed_hex: String,
    prover_tee_ikm_hex: String,
    ephemeral_seed_hex: String,
    quorum_seed_hex: String,
    quorum_public_key: String,
    ephemeral_public_key: String,
    operations: Vec<OperationKind>,
}

fn decode_32(value: &str) -> [u8; 32] {
    decode_lower_hex_array(value).expect("local testkit key must be 32-byte lowercase hex")
}

fn testkit() -> &'static Testkit {
    static TESTKIT: OnceLock<Testkit> = OnceLock::new();
    TESTKIT.get_or_init(|| {
        let testkit: Testkit =
            serde_json::from_str(TESTKIT_JSON).expect("local testkit fixture must be valid");
        assert_eq!(testkit.version, TESTKIT_VERSION);
        assert_eq!(testkit.operations, OPERATIONS);
        let ephemeral = P256Pair::from_master_seed(&decode_32(&testkit.ephemeral_seed_hex).into())
            .expect("ephemeral seed");
        let quorum = P256Pair::from_master_seed(&decode_32(&testkit.quorum_seed_hex).into())
            .expect("quorum seed");
        assert_eq!(
            hex::encode(ephemeral.public_key().to_bytes()),
            testkit.ephemeral_public_key
        );
        assert_eq!(
            hex::encode(quorum.public_key().to_bytes()),
            testkit.quorum_public_key
        );
        testkit
    })
}

/// Stable test-only QOS seeds, so the SDK pins the local server instead of
/// trusting whatever answers on the loopback port.
pub fn local_testkit_qos_seeds() -> ([u8; 32], [u8; 32]) {
    let testkit = testkit();
    (
        decode_32(&testkit.ephemeral_seed_hex),
        decode_32(&testkit.quorum_seed_hex),
    )
}

/// The testkit's prover policy signer and the stand-in prover's HPKE key
/// material.
pub(crate) fn testkit_prover_keys() -> (SigningKey, [u8; 32]) {
    let testkit = testkit();
    (
        SigningKey::from_bytes(&decode_32(&testkit.prover_policy_signer_seed_hex)),
        decode_32(&testkit.prover_tee_ikm_hex),
    )
}

fn public_of(private_key_hex: &str) -> [u8; 65] {
    let secret = decode_32(private_key_hex);
    let signing = p256::ecdsa::SigningKey::from_slice(&secret).expect("testkit P-256 scalar");
    signing
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .expect("uncompressed SEC1 point")
}

/// The provers a local enclave seals witnesses to.
pub enum LocalProverTrust {
    /// The stand-in prover: provers chaining to these anchors, under the
    /// testkit's prover policy signer.
    StandIn(Anchors),
    /// The live TEE provers of the image's network: the production vendor
    /// roots, under the policy signers the enclave image carries.
    Image,
}

impl LocalProverTrust {
    fn trust(self) -> ProverTrust {
        match self {
            Self::StandIn(anchors) => {
                let signer = testkit_prover_keys().0.verifying_key().to_bytes();
                ProverTrust {
                    signers: PolicySigners::new(NET.network.as_str(), vec![signer], 1)
                        .expect("testkit policy signer"),
                    anchors,
                }
            }
            Self::Image => ProverTrust::image(),
        }
    }
}

/// The explicitly unattested local state: custody backed by `wallet_secret`,
/// sealing to the provers `prover` names.
pub fn local_unattested_state(
    ephemeral: P256Pair,
    quorum: P256Pair,
    wallet_secret: [u8; 32],
    prover: LocalProverTrust,
) -> AppState {
    let testkit = testkit();
    let config = DiscoveryConfig {
        security_domain_id: sha256(testkit.security_domain_label.as_bytes()),
        release_id: testkit.release_id.clone(),
        quorum_key_id: testkit.quorum_key_id.clone(),
        quorum_key_epoch: 1,
    };
    let info = config.service_info(
        &crate::APP,
        sha256(testkit.manifest_label.as_bytes()),
        sha256(testkit.executable_label.as_bytes()),
        &quorum,
        &ephemeral,
    );
    AppState {
        info: Arc::new(info),
        runtime: Arc::new(Runtime {
            ephemeral: Arc::new(ephemeral),
            quorum: Arc::new(quorum),
            custody: Arc::new(LocalCustody {
                signing_key: SigningKey::from_bytes(&wallet_secret),
            }),
            provisioning_public: public_of(&testkit.provisioning_private_key_hex),
            grant_public: public_of(&testkit.grant_private_key_hex),
            prover: prover.trust(),
        }),
    }
}

struct LocalCustody {
    signing_key: SigningKey,
}

impl LocalCustody {
    fn own(&self, wallet: &WalletKey<'_>) -> Result<(), CustodyError> {
        if self.signing_key.verifying_key().as_bytes() != &wallet.public_key {
            return Err(CustodyError::Declined);
        }
        Ok(())
    }
}

#[async_trait]
impl Custody for LocalCustody {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        _timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError> {
        self.own(wallet)?;
        Ok(RawSignature {
            signature: Zeroizing::new(self.signing_key.sign(payload).to_bytes()),
            activity_id: "local-custody-bootstrap".to_owned(),
        })
    }
}
