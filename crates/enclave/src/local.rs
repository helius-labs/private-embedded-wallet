//! The unattested local testkit: pinned QOS keys and release labels in place
//! of an attestation. Never linked into an enclave binary.

use qos_p256::P256Pair;
use serde::Deserialize;
use zolana_tvc_protocol::digest::sha256;
use zolana_tvc_protocol::encoding::{decode_lower_hex_array, encode_lower_hex};

use crate::{App, Release, Service};

const TESTKIT_JSON: &str = include_str!("../../../packages/tvc-wallet/src/local-testkit.json");
/// The fixture's own format version, which the TypeScript testkit checks too.
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
    ephemeral_seed_hex: String,
    quorum_seed_hex: String,
    quorum_public_key: String,
    ephemeral_public_key: String,
}

/// `app` as the testkit release, under the keys a testkit client pins.
pub fn service(app: &App) -> Service {
    let testkit: Testkit = serde_json::from_str(TESTKIT_JSON).expect("local testkit fixture");
    assert_eq!(testkit.version, TESTKIT_VERSION);
    let ephemeral = pair(&testkit.ephemeral_seed_hex, &testkit.ephemeral_public_key);
    let quorum = pair(&testkit.quorum_seed_hex, &testkit.quorum_public_key);
    let release = Release {
        security_domain_id: sha256(testkit.security_domain_label.as_bytes()),
        release_id: testkit.release_id,
        quorum_key_id: testkit.quorum_key_id,
        quorum_key_epoch: 1,
    };
    let info = release.service_info(
        app,
        sha256(testkit.manifest_label.as_bytes()),
        sha256(testkit.executable_label.as_bytes()),
        &quorum,
        &ephemeral,
    );
    Service::new(info, ephemeral, quorum)
}

fn pair(seed_hex: &str, public_key_hex: &str) -> P256Pair {
    let seed: [u8; 32] = decode_lower_hex_array(seed_hex).expect("local testkit seed");
    let pair = P256Pair::from_master_seed(&seed.into()).expect("local testkit key");
    assert_eq!(
        encode_lower_hex(&pair.public_key().to_bytes()),
        public_key_hex
    );
    pair
}
