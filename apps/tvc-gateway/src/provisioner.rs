use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use serde::Deserialize;
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::{sign_p256_prehash, verify_p256_prehash};
use zolana_tvc_protocol::digest::descriptor_digest;
use zolana_tvc_protocol::{
    ClientGrant, ErrorCode, Network, PinnedReleaseAuthorities, ReleasePolicy, SignedReleasePolicy,
    WalletDescriptor, verify_signed_release_policy,
};

use crate::config::{ProvisioningConfig, load_signing_key};
use crate::enrollment::EnrollmentInput;
use crate::error::ApiError;

/// A network's release file, `packages/tvc-wallet/src/releases/<network>.json`,
/// as clients pin it. Its `qosIdentityPcrs` check Boot Proofs, which is the
/// clients' job, so they are not read here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseFile {
    release_policy: SignedReleasePolicy,
    release_authorities: PinnedReleaseAuthorities,
}

/// Holds the provisioning key and the release policy descriptors are issued
/// under. Signed descriptors are the enclave's only grant of access to a wallet.
pub struct Provisioner {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; 65],
    policy: ReleasePolicy,
}

impl Provisioner {
    /// Refuses to start under a release file for another network, or one
    /// that does not verify now.
    pub fn new(config: &ProvisioningConfig, network: Network) -> anyhow::Result<Self> {
        let (secret, public_key) = signing_key(config)?;
        let path = &config.release_path;
        let release: ReleaseFile = read_json(path)?;
        let policy = &release.release_policy.policy;
        anyhow::ensure!(
            policy.network == network,
            "{} is the {} release, and this gateway serves {network}",
            path.display(),
            policy.network
        );
        verify_signed_release_policy(
            &release.release_policy,
            &release.release_authorities,
            network,
            now_ms()?,
        )
        .map_err(|error| match error.code {
            ErrorCode::ExpiredRequest => anyhow::anyhow!(
                "the release policy in {} is valid from {} to {} (Unix ms), not now",
                path.display(),
                policy.valid_from_ms,
                policy.expires_at_ms
            ),
            code => anyhow::anyhow!(
                "the release policy in {} does not verify: {code}",
                path.display()
            ),
        })?;
        Ok(Self {
            secret,
            public_key,
            policy: release.release_policy.policy,
        })
    }

    /// Refuses to issue descriptors once the release has expired: clients
    /// would refuse its enclave. A new release and deploy fix it.
    pub fn check_current(&self, now_ms: u64) -> Result<(), ApiError> {
        if now_ms > self.policy.expires_at_ms {
            tracing::error!(
                expires_at_ms = self.policy.expires_at_ms,
                "the release policy has expired"
            );
            return Err(ApiError::ReleaseExpired);
        }
        Ok(())
    }

    /// One client key may drive every operation the release allows, for one
    /// Turnkey wallet. The enclave refuses a narrowed or reordered list.
    pub fn sign(&self, input: &EnrollmentInput) -> Result<WalletDescriptor, ApiError> {
        let mut descriptor = WalletDescriptor {
            version: API_VERSION,
            security_domain_id: self.policy.security_domain_id,
            network: self.policy.network,
            turnkey_organization_id: input.organization_id.clone(),
            turnkey_wallet_id: input.turnkey_wallet_id.clone(),
            address: input.solana_address.clone(),
            allowed_clients: vec![ClientGrant {
                client_public_key: input.client_public_key.to_vec(),
                allowed_operations: self.policy.allowed_operations.clone(),
            }],
            provisioning_signature: Vec::new(),
        };
        let digest = descriptor_digest(&descriptor).map_err(|error| {
            tracing::error!(?error, "descriptor did not canonicalize");
            ApiError::ProvisionerUnavailable
        })?;
        let signature = sign_p256_prehash(&self.secret, &digest).map_err(|error| {
            tracing::error!(?error, "descriptor signing failed");
            ApiError::ProvisionerUnavailable
        })?;
        descriptor.provisioning_signature = signature.to_vec();
        Ok(descriptor)
    }

    /// Accepts a descriptor this provisioner signed under the current release.
    pub fn verify(&self, descriptor: &WalletDescriptor) -> Result<(), ApiError> {
        let invalid = ApiError::InvalidDescriptor;
        if descriptor.version != API_VERSION
            || descriptor.security_domain_id != self.policy.security_domain_id
            || descriptor.network != self.policy.network
            || descriptor.allowed_clients.len() != 1
        {
            return Err(invalid);
        }
        let digest = descriptor_digest(descriptor).map_err(|_| invalid)?;
        verify_p256_prehash(
            &self.public_key,
            &digest,
            &descriptor.provisioning_signature,
        )
        .map_err(|_| invalid)
    }
}

pub fn now_ms() -> anyhow::Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

/// The provisioning key, which may also carry a `0x` prefix.
fn signing_key(config: &ProvisioningConfig) -> anyhow::Result<(Zeroizing<[u8; 32]>, [u8; 65])> {
    load_signing_key(
        "provisioning",
        config.private_key.trim().trim_start_matches("0x"),
        &config.expected_public_key,
    )
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zolana_tvc_protocol::OperationKind;

    pub const TEST_SECRET: [u8; 32] = [7; 32];

    pub fn provisioner() -> Provisioner {
        let secret = Zeroizing::new(TEST_SECRET);
        let public_key = crate::config::public_key_of(&secret).unwrap_or([0; 65]);
        Provisioner {
            secret,
            public_key,
            policy: test_policy(),
        }
    }

    pub fn test_policy() -> ReleasePolicy {
        ReleasePolicy {
            version: API_VERSION,
            release_id: "test".to_owned(),
            network: Network::Devnet,
            tvc_application_id: "test".to_owned(),
            security_domain_id: [9; 32],
            accepted_manifest_digests: Vec::new(),
            accepted_executable_digests: Vec::new(),
            quorum_key_id: "test".to_owned(),
            quorum_key_epoch: 1,
            quorum_public_key: Vec::new(),
            allowed_operations: vec![
                OperationKind::Bootstrap,
                OperationKind::Decrypt,
                OperationKind::Derive,
                OperationKind::TransactionKeys,
                OperationKind::Prove,
            ],
            max_encrypted_request_bytes: 262_144,
            max_encrypted_response_bytes: 262_144,
            turnkey_trust_root_id: "aws-nitro-root-g1".to_owned(),
            turnkey_proof_schema_versions: Vec::new(),
            valid_from_ms: 0,
            expires_at_ms: u64::MAX,
            revocation_epoch: 0,
        }
    }

    #[test]
    fn signed_descriptor_verifies_and_tampering_fails() {
        let provisioner = provisioner();
        let input = crate::enrollment::tests::input();
        let mut descriptor = provisioner.sign(&input).expect("signing failed");
        assert_eq!(provisioner.verify(&descriptor), Ok(()));
        assert_eq!(
            descriptor.allowed_clients[0].allowed_operations,
            test_policy().allowed_operations
        );
        descriptor.turnkey_wallet_id.push('x');
        assert_eq!(
            provisioner.verify(&descriptor),
            Err(ApiError::InvalidDescriptor)
        );
    }

    #[test]
    fn the_provisioning_key_may_carry_a_0x_prefix() {
        let config = |private_key: String| ProvisioningConfig {
            private_key,
            expected_public_key: hex::encode(
                crate::config::public_key_of(&TEST_SECRET).expect("valid key"),
            ),
            release_path: "unused".into(),
        };
        assert!(signing_key(&config(format!(" 0x{}\n", "07".repeat(32)))).is_ok());
        assert!(signing_key(&config("07".repeat(31))).is_err());
    }
}

#[cfg(test)]
mod release_file_tests {
    use zolana_tvc_protocol::release::{ReleaseAuthorityKey, sign_release_policy};
    use zolana_tvc_protocol::{ReleaseAuthoritySignature, SignedReleasePolicy};

    use super::tests::{TEST_SECRET, test_policy};
    use super::*;

    const AUTHORITY_SECRET: [u8; 32] = [8; 32];

    /// A release file for `policy`, signed by a test authority, with the PCRs
    /// clients read, written where only this test reads it.
    fn release_file(name: &str, policy: ReleasePolicy) -> std::path::PathBuf {
        let signature = sign_release_policy(&policy, &AUTHORITY_SECRET).expect("signs");
        let public_key = crate::config::public_key_of(&AUTHORITY_SECRET).expect("valid key");
        let file = serde_json::json!({
            "releasePolicy": SignedReleasePolicy {
                policy,
                authority_set_id: "test-set".to_owned(),
                signatures: vec![ReleaseAuthoritySignature {
                    key_id: "test-authority".to_owned(),
                    signature: signature.to_vec(),
                }],
            },
            "releaseAuthorities": PinnedReleaseAuthorities {
                authority_set_id: "test-set".to_owned(),
                threshold: 1,
                keys: vec![ReleaseAuthorityKey {
                    key_id: "test-authority".to_owned(),
                    public_key: public_key.to_vec(),
                }],
                minimum_revocation_epoch: 0,
            },
            "qosIdentityPcrs": { "0": "00" },
        });
        let path = std::env::temp_dir().join(format!(
            "tvc-gateway-release-{}-{name}.json",
            std::process::id()
        ));
        fs::write(&path, file.to_string()).expect("the release file writes");
        path
    }

    fn provisioner(path: std::path::PathBuf, network: Network) -> anyhow::Result<Provisioner> {
        let config = ProvisioningConfig {
            private_key: hex::encode(TEST_SECRET),
            expected_public_key: hex::encode(
                crate::config::public_key_of(&TEST_SECRET).expect("valid key"),
            ),
            release_path: path,
        };
        Provisioner::new(&config, network)
    }

    #[test]
    fn a_release_file_for_the_gateways_network_starts_it() {
        let path = release_file("devnet", test_policy());
        let started = provisioner(path.clone(), Network::Devnet);
        let refused = provisioner(path.clone(), Network::Mainnet);
        let _ = fs::remove_file(path);
        assert!(started.is_ok(), "{:?}", started.err());
        let error = refused
            .err()
            .expect("a devnet release starts a mainnet gateway");
        assert!(
            error
                .to_string()
                .ends_with("is the devnet release, and this gateway serves mainnet"),
            "{error}"
        );
    }

    #[test]
    fn an_expired_or_unsigned_release_does_not_start() {
        let expired = ReleasePolicy {
            valid_from_ms: 1,
            expires_at_ms: 2,
            ..test_policy()
        };
        let path = release_file("expired", expired);
        let error = provisioner(path.clone(), Network::Devnet).err();
        let _ = fs::remove_file(path);
        let error = error.expect("an expired release starts the gateway");
        assert!(
            error
                .to_string()
                .ends_with("valid from 1 to 2 (Unix ms), not now"),
            "{error}"
        );

        let path = release_file("tampered", test_policy());
        let tampered = fs::read_to_string(&path)
            .expect("the release file reads")
            .replace("\"releaseId\":\"test\"", "\"releaseId\":\"other\"");
        fs::write(&path, tampered).expect("the release file writes");
        let error = provisioner(path.clone(), Network::Devnet).err();
        let _ = fs::remove_file(path);
        let error = error.expect("a tampered release starts the gateway");
        assert!(
            error
                .to_string()
                .ends_with("does not verify: InvalidSignature"),
            "{error}"
        );
    }

    #[test]
    fn descriptors_stop_when_the_release_expires() {
        let provisioner = super::tests::provisioner();
        let expires = test_policy().expires_at_ms;
        assert_eq!(provisioner.check_current(expires), Ok(()));
        let mut expiring = provisioner;
        expiring.policy.expires_at_ms = 10;
        assert_eq!(expiring.check_current(10), Ok(()));
        assert_eq!(expiring.check_current(11), Err(ApiError::ReleaseExpired));
    }
}
