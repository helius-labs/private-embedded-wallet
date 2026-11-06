use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::{sign_p256_prehash, verify_p256_prehash};
use zolana_tvc_protocol::digest::descriptor_digest;
use zolana_tvc_protocol::{
    ClientGrant, PinnedReleaseAuthorities, ReleasePolicy, SignedReleasePolicy, WalletDescriptor,
    verify_signed_release_policy,
};

use crate::config::{ProvisioningConfig, load_signing_key};
use crate::enrollment::EnrollmentInput;
use crate::error::ApiError;

/// Holds the provisioning key and the release policy descriptors are issued
/// under. Signed descriptors are the enclave's only grant of access to a wallet.
pub struct Provisioner {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; 65],
    policy: ReleasePolicy,
}

impl Provisioner {
    pub fn new(config: &ProvisioningConfig) -> anyhow::Result<Self> {
        let (secret, public_key) = signing_key(config)?;
        let signed: SignedReleasePolicy = read_json(&config.release_policy_path)?;
        let authorities: PinnedReleaseAuthorities = read_json(&config.release_authorities_path)?;
        verify_signed_release_policy(&signed, &authorities, now_ms()?)
            .map_err(|error| anyhow::anyhow!("release policy does not verify: {error:?}"))?;
        Ok(Self {
            secret,
            public_key,
            policy: signed.policy,
        })
    }

    /// One client key may drive every operation the release allows, for one
    /// Turnkey wallet. The enclave refuses a narrowed or reordered list.
    pub fn sign(&self, input: &EnrollmentInput) -> Result<WalletDescriptor, ApiError> {
        let mut descriptor = WalletDescriptor {
            version: API_VERSION,
            security_domain_id: self.policy.security_domain_id,
            environment: self.policy.environment,
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
            || descriptor.environment != self.policy.environment
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

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> anyhow::Result<T> {
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
            version: 1,
            release_id: "test".to_owned(),
            environment: zolana_tvc_protocol::Environment::Development,
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
            release_policy_path: "unused".into(),
            release_authorities_path: "unused".into(),
        };
        assert!(signing_key(&config(format!(" 0x{}\n", "07".repeat(32)))).is_ok());
        assert!(signing_key(&config("07".repeat(31))).is_err());
    }
}

#[cfg(test)]
mod committed_policy_tests {
    use super::*;

    #[test]
    fn the_committed_release_policy_verifies_against_the_committed_authorities() {
        let signed =
            read_json::<SignedReleasePolicy>(std::path::Path::new("configs/release-policy.json"))
                .expect("configs/release-policy.json does not parse");
        let authorities = read_json::<PinnedReleaseAuthorities>(std::path::Path::new(
            "configs/release-authorities.json",
        ))
        .expect("configs/release-authorities.json does not parse");
        let during_validity = signed.policy.valid_from_ms.saturating_add(1);
        assert_eq!(
            verify_signed_release_policy(&signed, &authorities, during_validity),
            Ok(())
        );
    }
}
