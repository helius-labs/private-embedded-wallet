//! Service configuration: the shared `config.yaml`, then one network's
//! overlay (`devnet.yaml` or `mainnet.yaml` beside it), then `TVC_GATEWAY_`
//! env overrides (nested fields split on `__`, e.g.
//! `TVC_GATEWAY_PROVISIONING__PRIVATE_KEY`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;
use zeroize::Zeroizing;
use zolana_tvc_protocol::Network;

/// The shared settings every network overlay sits on, in the overlay's directory.
pub const BASE_FILE: &str = "config.yaml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Dev,
    Prod,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The network this gateway serves; its release file must be for it too.
    pub network: Network,
    pub stage: Stage,
    pub listen: SocketAddr,
    pub metrics: MetricsConfig,
    /// `Authorization` value gatekeeper sends on every origin request. Secret.
    pub origin_auth_header: String,
    pub dev_api: DevApiConfig,
    pub enclave: EnclaveConfig,
    pub turnkey: TurnkeyConfig,
    pub provisioning: ProvisioningConfig,
    pub wallet_grant: WalletGrantConfig,
    pub enrollment: EnrollmentConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentConfig {
    /// The hosts clients reach this gateway at, such as gatekeeper's
    /// `devnet.helius-rpc.com` and `beta-devnet.helius-rpc.com`: a wallet owner
    /// signs the Sign-In With Solana message for the one it calls.
    pub domains: Vec<String>,
}

/// Helius dev-api (`ts-services/dev-api` in helius-labs/monorepo), which
/// resolves the API key a direct caller sends to its project.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevApiConfig {
    /// Without a trailing slash, such as `https://dev-api.helius.xyz/v0`.
    pub base_url: String,
    pub project_cache_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub statsd_endpoint: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveConfig {
    /// TVC public ingress, without a trailing slash.
    pub base_url: String,
    pub request_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub max_in_flight_per_project: u32,
    pub replay_window_secs: u64,
    pub replay_max_entries: usize,
    /// Redis every gateway task shares its replay guard through, such as
    /// `rediss://host:6379/2`. Absent, each process keeps its own.
    #[serde(default)]
    pub replay_redis_url: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyConfig {
    pub api_base_url: String,
    /// Organization that owns the network's TVC application; Boot Proofs are
    /// read here.
    pub tvc_organization_id: String,
    pub boot_proof_api_key: TurnkeyApiKey,
    /// A key in the Helius WaaS organization, whose sub-orgs hold every
    /// end-user wallet.
    pub waas_api_key: TurnkeyApiKey,
    pub ownership_cache_secs: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyApiKey {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningConfig {
    /// 32-byte P-256 secret, hex. Signs wallet descriptors. Secret.
    pub private_key: String,
    /// Uncompressed SEC1 hex of the key the enclave is built with.
    pub expected_public_key: String,
    /// The network's release file, as clients pin it: the signed release
    /// policy descriptors are issued under and the authority set it verifies
    /// against. Relative to the working directory.
    pub release_path: PathBuf,
    /// How long a descriptor admits its client key, from the time the owner
    /// signed the enrollment. The client enrolls again near the end.
    pub descriptor_ttl_secs: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletGrantConfig {
    /// 32-byte P-256 secret, hex. Signs wallet grants. Secret.
    pub private_key: String,
    /// Uncompressed SEC1 hex of the grant key the enclave is built with.
    pub expected_public_key: String,
    pub ttl_secs: u64,
    /// Client key IDs (`spr-client-p256-…`) refused a wallet grant.
    #[serde(default)]
    pub revoked_client_key_ids: Vec<String>,
}

pub const MIN_SECRET_LEN: usize = 32;

/// The P-256 key `<name>.private_key` holds, as 32 bytes of hex, and its
/// uncompressed SEC1 public key, which must be `<name>.expected_public_key`.
pub fn load_signing_key(
    name: &str,
    private_key_hex: &str,
    expected_public_key: &str,
) -> anyhow::Result<(Zeroizing<[u8; 32]>, [u8; 65])> {
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(private_key_hex, secret.as_mut_slice())
        .with_context(|| format!("{name}.private_key must be 32 bytes of hex"))?;
    let public_key =
        public_key_of(&secret).with_context(|| format!("{name}.private_key is not a P-256 key"))?;
    anyhow::ensure!(
        hex::encode(public_key) == expected_public_key,
        "{name}.private_key does not match {name}.expected_public_key"
    );
    Ok((secret, public_key))
}

/// The uncompressed SEC1 public key of a P-256 secret.
pub fn public_key_of(secret: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
    let point = SecretKey::from_slice(secret)?
        .public_key()
        .to_encoded_point(false);
    Ok(point.as_bytes().try_into()?)
}

/// The shared config and the network overlay at `overlay`, such as
/// `configs/devnet.yaml`, under the environment.
pub fn load(overlay: &Path) -> anyhow::Result<Config> {
    let config: Config = files(overlay)?
        .merge(Env::prefixed("TVC_GATEWAY_").split("__"))
        .extract()?;
    config.validate()?;
    Ok(config)
}

/// `config.yaml` beside `overlay`, then `overlay`. Both must exist.
fn files(overlay: &Path) -> anyhow::Result<Figment> {
    anyhow::ensure!(
        overlay.file_name().is_some_and(|name| name != BASE_FILE),
        "--config names a network overlay, such as configs/devnet.yaml, not {}",
        overlay.display()
    );
    Ok(Figment::new()
        .merge(Yaml::file_exact(overlay.with_file_name(BASE_FILE)))
        .merge(Yaml::file_exact(overlay)))
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.origin_auth_header.len() >= MIN_SECRET_LEN,
            "origin_auth_header must be at least {MIN_SECRET_LEN} bytes"
        );
        anyhow::ensure!(
            ["https://", "http://"]
                .iter()
                .any(|scheme| self.enclave.base_url.starts_with(scheme)),
            "enclave.base_url must be the {} enclave's URL, not {:?}",
            self.network,
            self.enclave.base_url
        );
        anyhow::ensure!(
            is_canonical_uuid(&self.turnkey.tvc_organization_id),
            "turnkey.tvc_organization_id must be the {} TVC application's organization, not {:?}",
            self.network,
            self.turnkey.tvc_organization_id
        );
        anyhow::ensure!(
            !self.enclave.base_url.ends_with('/'),
            "enclave.base_url must not end with '/'"
        );
        anyhow::ensure!(
            !self.dev_api.base_url.ends_with('/'),
            "dev_api.base_url must not end with '/'"
        );
        anyhow::ensure!(
            self.provisioning.descriptor_ttl_secs > 0,
            "provisioning.descriptor_ttl_secs must be positive"
        );
        anyhow::ensure!(
            self.enclave.max_in_flight_per_project > 0,
            "enclave.max_in_flight_per_project must be positive"
        );
        anyhow::ensure!(
            self.enclave.replay_window_secs > 0 && self.enclave.replay_max_entries > 0,
            "enclave replay window and capacity must be positive"
        );
        anyhow::ensure!(
            !self.enrollment.domains.is_empty()
                && self.enrollment.domains.iter().all(|domain| {
                    !domain.is_empty() && !domain.contains(|c: char| c.is_whitespace() || c == '/')
                }),
            "enrollment.domains must list hosts, such as beta-devnet.helius-rpc.com"
        );
        Ok(())
    }
}

/// A lowercase hyphenated UUID, as Turnkey writes its IDs.
pub fn is_canonical_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

#[cfg(test)]
mod tests {
    use figment::providers::Serialized;

    use super::*;

    /// A committed network overlay with the secrets the environment supplies
    /// and `environment` on top, as a deployment loads it.
    fn committed_config(
        overlay: &str,
        origin_auth_header: &str,
        environment: serde_json::Value,
    ) -> anyhow::Result<Config> {
        let secrets = serde_json::json!({
            "origin_auth_header": origin_auth_header,
            "provisioning": { "private_key": "11".repeat(32) },
            "wallet_grant": { "private_key": "06".repeat(32) },
            "turnkey": {
                "boot_proof_api_key": { "public_key": "02", "private_key": "01" },
                "waas_api_key": { "public_key": "02", "private_key": "01" },
            },
        });
        let config: Config = files(Path::new(overlay))?
            .merge(Serialized::defaults(secrets))
            .merge(Serialized::defaults(environment))
            .extract()?;
        config.validate()?;
        Ok(config)
    }

    fn devnet_config_with(origin_auth_header: &str) -> anyhow::Result<Config> {
        committed_config(
            "configs/devnet.yaml",
            origin_auth_header,
            serde_json::json!({}),
        )
    }

    #[test]
    fn the_devnet_overlay_serves_devnet_at_both_gatekeeper_hosts() {
        let config =
            devnet_config_with(&"a".repeat(MIN_SECRET_LEN)).expect("the committed config loads");
        assert_eq!(config.network, Network::Devnet);
        assert_eq!(config.provisioning.descriptor_ttl_secs, 86_400);
        assert_eq!(
            config.enrollment.domains,
            ["devnet.helius-rpc.com", "beta-devnet.helius-rpc.com"]
        );
        assert_eq!(
            config.provisioning.release_path,
            Path::new("releases/devnet.json")
        );
        assert_eq!(
            config.provisioning.expected_public_key,
            "046e852f2eb1bc79e2ed3cdb57fa7e2f75720fe53032f6aedcfbdfceb67f635691540564e208ca675f4d8b33291aa1388a0067dadc4f1d04519aab320bbd2cce64"
        );
        assert_eq!(
            config.wallet_grant.expected_public_key,
            "04d92dfa9ba9aafd471ff9ffbf454b9a11b14858a8c2edb4f79a4ea4b4dba8ca5cac9ec06d9bb5576db72d07e087ac6aadf72e4eb31323aafaf9dbd133d26f4dc7"
        );
    }

    /// Mainnet has no Turnkey application yet: its overlay refuses to start
    /// until the enclave URL and organization are filled in.
    #[test]
    fn the_mainnet_overlay_needs_its_turnkey_application() {
        let secret = "a".repeat(MIN_SECRET_LEN);
        let error = committed_config("configs/mainnet.yaml", &secret, serde_json::json!({}))
            .err()
            .expect("the mainnet overlay starts without an enclave");
        assert!(
            error
                .to_string()
                .starts_with("enclave.base_url must be the mainnet enclave's URL"),
            "{error}"
        );
        let filled = serde_json::json!({
            "enclave": { "base_url": "https://app-mainnet.example" },
            "turnkey": { "tvc_organization_id": "00000000-0000-4000-8000-000000000001" },
        });
        let config = committed_config("configs/mainnet.yaml", &secret, filled)
            .expect("the filled-in mainnet overlay loads");
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.provisioning.descriptor_ttl_secs, 86_400);
        assert_eq!(
            config.enrollment.domains,
            ["mainnet.helius-rpc.com", "beta-mainnet.helius-rpc.com"]
        );
        assert_eq!(
            config.provisioning.release_path,
            Path::new("releases/mainnet.json")
        );
        assert_eq!(
            config.provisioning.expected_public_key,
            "04f87ca34fcd2b78f57321c662a66395e400744a1951655ed77fbd1482a84e7590359b5f9b157a84489db68b02984c90b641a05deec3cdfd67dd990aecc89a58e0"
        );
        assert_eq!(
            config.wallet_grant.expected_public_key,
            "048929b53b1b9d0b22be43a306583cdb9233e48da9e260cde61c6f93ceb1e5ea43973c01057c98779d47c03e5a5ed8e2ed1e0bc3d9685bc6deea2474d44fd57d5d"
        );
    }

    #[test]
    fn the_shared_config_alone_is_not_a_network() {
        let error = files(Path::new("configs/config.yaml"))
            .expect_err("the shared config loads as an overlay");
        assert!(error.to_string().contains("network overlay"), "{error}");
        assert!(
            committed_config("configs/testnet.yaml", "", serde_json::json!({})).is_err(),
            "a missing overlay loads"
        );
    }

    #[test]
    fn a_signing_key_must_be_hex_and_match_its_public_key() {
        let secret = "07".repeat(32);
        let public = hex::encode(public_key_of(&[7; 32]).expect("valid key"));
        let (loaded, loaded_public) =
            load_signing_key("test", &secret, &public).expect("the key loads");
        assert_eq!(
            (*loaded, hex::encode(loaded_public)),
            ([7; 32], public.clone())
        );
        for (secret, public) in [
            (format!("0x{secret}"), public.as_str()),
            ("07".repeat(31), public.as_str()),
            ("00".repeat(32), public.as_str()),
            (secret.clone(), "04"),
        ] {
            assert!(
                load_signing_key("test", &secret, public).is_err(),
                "{secret}"
            );
        }
    }

    #[test]
    fn the_committed_config_requires_a_full_length_origin_secret() {
        assert!(devnet_config_with(&"a".repeat(MIN_SECRET_LEN)).is_ok());
        assert!(devnet_config_with("").is_err());
        assert!(devnet_config_with("Bearer short").is_err());
    }
}
