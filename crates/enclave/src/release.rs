//! What a release is, and what it advertises at `/v1/info`.

use qos_p256::P256Pair;
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES, MAX_ENCRYPTED_RESPONSE_BYTES,
};
use zolana_tvc_protocol::encoding::decode_lower_hex_array;
use zolana_tvc_protocol::types::{Network, OperationKind, ServiceInfo};

const SPR_NETWORK: &str = match option_env!("SPR_NETWORK") {
    Some(network) => network,
    None => "devnet",
};

const _: () = assert!(
    eq(SPR_NETWORK, "devnet") || eq(SPR_NETWORK, "mainnet"),
    "SPR_NETWORK must be devnet or mainnet"
);

/// The network this image was built for: `SPR_NETWORK`, or devnet.
pub const NETWORK: Network = if eq(SPR_NETWORK, "mainnet") {
    Network::Mainnet
} else {
    Network::Devnet
};

const fn eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// What an application is in every release.
pub struct App {
    pub operations: &'static [OperationKind],
    pub proof_type: &'static str,
}

// The arguments a QOS manifest starts a release with. Not a doc comment: clap would print it.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct Release {
    #[arg(long, value_parser = security_domain_id)]
    pub security_domain_id: [u8; 32],

    #[arg(long, value_parser = nonempty)]
    pub release_id: String,

    #[arg(long, value_parser = nonempty)]
    pub quorum_key_id: String,

    #[arg(long, value_parser = positive_epoch)]
    pub quorum_key_epoch: u64,
}

impl Release {
    pub fn service_info(
        self,
        app: &App,
        manifest_digest: [u8; 32],
        executable_digest: [u8; 32],
        quorum: &P256Pair,
        ephemeral: &P256Pair,
    ) -> ServiceInfo {
        ServiceInfo {
            version: API_VERSION,
            network: NETWORK,
            security_domain_id: self.security_domain_id,
            release_id: self.release_id,
            manifest_digest,
            executable_digest,
            quorum_public_key: quorum.public_key().to_bytes(),
            quorum_key_id: self.quorum_key_id,
            quorum_key_epoch: self.quorum_key_epoch,
            ephemeral_public_key: ephemeral.public_key().to_bytes(),
            supported_operations: app.operations.to_vec(),
            max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES,
            max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES,
            proof_type: app.proof_type.to_owned(),
        }
    }
}

fn security_domain_id(value: &str) -> Result<[u8; 32], String> {
    decode_lower_hex_array(value)
        .map_err(|_| "must be exactly 32 bytes of lowercase unprefixed hex".to_owned())
}

fn nonempty(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("must not be empty".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn positive_epoch(value: &str) -> Result<u64, String> {
    let epoch = value
        .parse::<u64>()
        .map_err(|_| "must be a canonical positive u64".to_owned())?;
    if epoch == 0 || epoch.to_string() != value {
        return Err("must be a canonical positive u64".to_owned());
    }
    Ok(epoch)
}
