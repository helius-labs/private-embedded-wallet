//! Independently pinned release-policy signatures.
//!
//! Signatures cover `RELEASE_POLICY_DOMAIN || 0x00 || JCS(policy)` with
//! 64-byte raw low-S P-256. Empty signatures fail closed. Duplicate and
//! unknown key IDs do not count toward the threshold.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID};
use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::release_policy_digest;
use crate::encoding::{decimal_u64, hex, jcs_serialize};
use crate::error::{ErrorCode, TvcError};
use crate::types::{ClientAuthorizationScheme, ReleasePolicy, SignedReleasePolicy};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorityKey {
    pub key_id: String,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedReleaseAuthorities {
    pub authority_set_id: String,
    pub threshold: u8,
    pub keys: Vec<ReleaseAuthorityKey>,
    /// Policies below the epoch are revoked.
    #[serde(with = "decimal_u64")]
    pub minimum_revocation_epoch: u64,
}

pub fn policy_signing_digest(policy: &ReleasePolicy) -> Result<[u8; 32], TvcError> {
    let canonical = jcs_serialize(policy)?;
    Ok(release_policy_digest(canonical.as_bytes()))
}

pub fn sign_release_policy(
    policy: &ReleasePolicy,
    secret: &[u8; 32],
) -> Result<[u8; 64], TvcError> {
    sign_p256_prehash(secret, &policy_signing_digest(policy)?)
}

pub fn verify_signed_release_policy(
    signed: &SignedReleasePolicy,
    authorities: &PinnedReleaseAuthorities,
    now_ms: u64,
) -> Result<(), TvcError> {
    if signed.policy.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    crate::types::reject_production_environment(signed.policy.environment)?;
    if authorities.threshold == 0 || authorities.keys.is_empty() {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.authority_set_id != authorities.authority_set_id {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.policy.turnkey_trust_root_id != EXPECTED_TURNKEY_TRUST_ROOT_ID {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.policy.revocation_epoch < authorities.minimum_revocation_epoch {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if now_ms < signed.policy.valid_from_ms || now_ms > signed.policy.expires_at_ms {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    if signed.signatures.is_empty() {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }

    let mut by_id = HashMap::new();
    for key in &authorities.keys {
        if by_id
            .insert(key.key_id.as_str(), key.public_key.as_slice())
            .is_some()
        {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
    }

    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();
    for signature in &signed.signatures {
        if !seen.insert(signature.key_id.as_str()) {
            duplicates.insert(signature.key_id.as_str());
        }
    }

    let digest = policy_signing_digest(&signed.policy)?;
    let mut accepted = 0u8;
    for signature in &signed.signatures {
        if duplicates.contains(signature.key_id.as_str()) {
            continue;
        }
        let Some(public) = by_id.get(signature.key_id.as_str()) else {
            continue;
        };
        if signature.scheme != ClientAuthorizationScheme::P256Sha256 {
            return Err(TvcError::new(ErrorCode::InvalidSignature));
        }
        verify_p256_prehash(public, &digest, &signature.signature)?;
        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| TvcError::new(ErrorCode::ReleasePolicyInvalid))?;
    }
    if accepted < authorities.threshold {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    Ok(())
}
