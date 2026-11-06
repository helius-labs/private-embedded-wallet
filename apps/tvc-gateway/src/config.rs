//! Service configuration: YAML file with `TVC_GATEWAY_` env overrides
//! (nested fields split on `__`, e.g. `TVC_GATEWAY_PROVISIONING__PRIVATE_KEY`).

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Dev,
    Prod,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
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
    /// Organization that owns the TVC application; Boot Proofs are read here.
    pub tvc_organization_id: String,
    /// Helius WaaS organization; every end-user wallet is in one of its sub-orgs.
    pub waas_parent_organization_id: String,
    pub boot_proof_api_key: TurnkeyApiKey,
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
    /// `SignedReleasePolicy` JSON the clients pin.
    pub release_policy_path: PathBuf,
    /// `PinnedReleaseAuthorities` JSON the policy must verify against.
    pub release_authorities_path: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletGrantConfig {
    /// 32-byte P-256 secret, hex. Signs wallet grants. Secret.
    pub private_key: String,
    /// Uncompressed SEC1 hex of the grant key the enclave is built with.
    pub expected_public_key: String,
    pub ttl_secs: u64,
    /// Client key IDs (`tvc-browser-p256-…`) refused a wallet grant.
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

pub fn load(path: &str) -> anyhow::Result<Config> {
    let config: Config = Figment::new()
        .merge(Yaml::file(path))
        .merge(Env::prefixed("TVC_GATEWAY_").split("__"))
        .extract()?;
    config.validate()?;
    Ok(config)
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.origin_auth_header.len() >= MIN_SECRET_LEN,
            "origin_auth_header must be at least {MIN_SECRET_LEN} bytes"
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

#[cfg(test)]
mod tests {
    use figment::providers::Serialized;

    use super::*;

    fn committed_config_with(origin_auth_header: &str) -> anyhow::Result<Config> {
        let secrets = serde_json::json!({
            "origin_auth_header": origin_auth_header,
            "provisioning": { "private_key": "11".repeat(32) },
            "wallet_grant": { "private_key": "06".repeat(32) },
            "turnkey": {
                "boot_proof_api_key": { "public_key": "02", "private_key": "01" },
                "waas_api_key": { "public_key": "02", "private_key": "01" },
            },
        });
        let config: Config = Figment::new()
            .merge(Yaml::file("configs/config.yaml"))
            .merge(Serialized::defaults(secrets))
            .extract()?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn the_committed_config_enrolls_at_both_gatekeeper_hosts() {
        let config =
            committed_config_with(&"a".repeat(MIN_SECRET_LEN)).expect("the committed config loads");
        assert_eq!(
            config.enrollment.domains,
            ["devnet.helius-rpc.com", "beta-devnet.helius-rpc.com"]
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
        assert!(committed_config_with(&"a".repeat(MIN_SECRET_LEN)).is_ok());
        assert!(committed_config_with("").is_err());
        assert!(committed_config_with("Bearer short").is_err());
    }
}
