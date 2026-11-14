//! Enrollment: the wallet owner signs, through Turnkey, a Sign-In With Solana
//! message naming this gateway, the wallet, the client key and the time, and
//! the gateway answers with a descriptor for that client key.

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use spr_tvc_protocol::Network;
use spr_tvc_protocol::constants::MAX_CLOCK_SKEW_MS;
use spr_tvc_protocol::crypto::parse_uncompressed_sec1;

use crate::config::is_canonical_uuid;
use crate::error::ApiError;

pub const STATEMENT: &str = "Authorize this client key to use your private wallet.";
const MAX_ENROLLMENT_AGE_MS: u64 = 5 * 60 * 1_000;

/// A device's enrollment, signed by the wallet owner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    /// The wallet's Turnkey sub-organization, named after the caller's project.
    pub organization_id: String,
    pub turnkey_wallet_id: String,
    /// The wallet's address, base58.
    pub solana_address: String,
    /// Uncompressed SEC1 P-256 key, lowercase hex.
    pub client_public_key: String,
    /// When the owner signed, in Unix milliseconds; valid for five minutes.
    pub issued_at_ms: u64,
    /// Ed25519 signature by the wallet address over the enrollment's Sign-In With
    /// Solana message, hex.
    pub owner_signature: String,
}

/// A validated enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentInput {
    pub organization_id: String,
    pub turnkey_wallet_id: String,
    pub solana_address: String,
    pub owner_public_key: [u8; 32],
    pub client_public_key: [u8; 65],
    /// When the owner signed, in Unix ms.
    pub issued_at_ms: u64,
}

pub struct Enrollment {
    network: Network,
    domains: Vec<String>,
}

impl Enrollment {
    /// `domains` are the hosts clients reach this gateway, which serves
    /// `network`, at.
    pub fn new(network: Network, domains: &[String]) -> Self {
        Self {
            network,
            domains: domains.to_vec(),
        }
    }

    /// The enrollment the wallet address signed within the last five minutes.
    pub fn verify(
        &self,
        request: &EnrollmentRequest,
        now_ms: u64,
    ) -> Result<EnrollmentInput, ApiError> {
        let fresh = request.issued_at_ms <= now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            && now_ms.saturating_sub(request.issued_at_ms) <= MAX_ENROLLMENT_AGE_MS;
        if !fresh {
            return Err(ApiError::StaleEnrollment);
        }
        let input = validate(request)?;
        // The owner signed for the host it called, one of this gateway's.
        for domain in &self.domains {
            let message =
                message(domain, self.network, request).ok_or(ApiError::InvalidEnrollmentRequest)?;
            if verify_owner_signature(&input, &message, &request.owner_signature).is_ok() {
                return Ok(input);
            }
        }
        Err(ApiError::InvalidOwnerEnrollmentSignature)
    }
}

/// The Sign-In With Solana message the wallet owner signs: the gateway's
/// `domain`, the address, [`STATEMENT`], the gateway's network as the chain,
/// the five minutes it is valid for, and the sub-organization, wallet and
/// client key as resources. Only validated fields may go in, so none holds a
/// newline.
pub fn message(domain: &str, network: Network, request: &EnrollmentRequest) -> Option<String> {
    let issued_at = rfc3339_millis(request.issued_at_ms)?;
    let expires_at = rfc3339_millis(request.issued_at_ms.checked_add(MAX_ENROLLMENT_AGE_MS)?)?;
    Some(format!(
        "{domain} wants you to sign in with your Solana account:\n\
         {address}\n\n\
         {STATEMENT}\n\n\
         Version: 1\n\
         Chain ID: {network}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expires_at}\n\
         Resources:\n\
         - urn:turnkey:organization:{organization}\n\
         - urn:turnkey:wallet:{wallet}\n\
         - urn:spr-tvc:client-key:{client_key}",
        address = request.solana_address,
        organization = request.organization_id,
        wallet = request.turnkey_wallet_id,
        client_key = request.client_public_key,
    ))
}

fn validate(request: &EnrollmentRequest) -> Result<EnrollmentInput, ApiError> {
    let invalid = ApiError::InvalidEnrollmentRequest;
    if !is_canonical_uuid(&request.organization_id)
        || !is_canonical_uuid(&request.turnkey_wallet_id)
    {
        return Err(invalid);
    }
    let owner_public_key = solana_public_key(&request.solana_address).ok_or(invalid)?;
    let client_public_key = client_public_key(&request.client_public_key).ok_or(invalid)?;
    Ok(EnrollmentInput {
        organization_id: request.organization_id.clone(),
        turnkey_wallet_id: request.turnkey_wallet_id.clone(),
        solana_address: request.solana_address.clone(),
        owner_public_key,
        client_public_key,
        issued_at_ms: request.issued_at_ms,
    })
}

/// `2027-01-15T08:00:00.000Z`, as JavaScript's `Date.prototype.toISOString`.
fn rfc3339_millis(ms: u64) -> Option<String> {
    let at = DateTime::<Utc>::from_timestamp_millis(i64::try_from(ms).ok()?)?;
    Some(at.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn verify_owner_signature(
    input: &EnrollmentInput,
    message: &str,
    signature_hex: &str,
) -> Result<(), ApiError> {
    let invalid = ApiError::InvalidOwnerEnrollmentSignature;
    let mut signature = [0u8; 64];
    hex::decode_to_slice(signature_hex, &mut signature).map_err(|_| invalid)?;
    let owner = VerifyingKey::from_bytes(&input.owner_public_key).map_err(|_| invalid)?;
    owner
        .verify_strict(message.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| invalid)
}

fn solana_public_key(address: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let written = bs58::decode(address).onto(&mut bytes).ok()?;
    (written == 32 && bs58::encode(bytes).into_string() == address).then_some(bytes)
}

fn client_public_key(value: &str) -> Option<[u8; 65]> {
    let mut bytes = [0u8; 65];
    let lowercase = value.bytes().all(|b| !b.is_ascii_uppercase());
    hex::decode_to_slice(value, &mut bytes).ok()?;
    parse_uncompressed_sec1(&bytes).ok()?;
    lowercase.then_some(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    pub const DOMAIN: &str = "beta-devnet.helius-rpc.com";
    pub const NOW: u64 = 1_800_000_000_000;

    pub fn enrollment(domains: &[&str]) -> Enrollment {
        let domains: Vec<String> = domains.iter().map(|&domain| domain.to_owned()).collect();
        Enrollment::new(Network::Devnet, &domains)
    }

    pub fn owner() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    pub fn client_public_hex() -> String {
        let secret = p256::SecretKey::from_slice(&[5; 32]).expect("test client key is invalid");
        hex::encode(secret.public_key().to_encoded_point(false).as_bytes())
    }

    /// An enrollment signed by [`owner`] at `issued_at_ms`.
    pub fn signed_request(issued_at_ms: u64) -> EnrollmentRequest {
        let mut request = EnrollmentRequest {
            organization_id: "1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b".to_owned(),
            turnkey_wallet_id: "2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d".to_owned(),
            solana_address: bs58::encode(owner().verifying_key().to_bytes()).into_string(),
            client_public_key: client_public_hex(),
            issued_at_ms,
            owner_signature: String::new(),
        };
        request.owner_signature = sign(&owner(), DOMAIN, &request);
        request
    }

    fn sign(signer: &SigningKey, domain: &str, request: &EnrollmentRequest) -> String {
        sign_for(signer, domain, Network::Devnet, request)
    }

    fn sign_for(
        signer: &SigningKey,
        domain: &str,
        network: Network,
        request: &EnrollmentRequest,
    ) -> String {
        let message = message(domain, network, request).expect("the test request formats");
        hex::encode(signer.sign(message.as_bytes()).to_bytes())
    }

    pub fn input() -> EnrollmentInput {
        enrollment(&[DOMAIN])
            .verify(&signed_request(NOW), NOW)
            .expect("test request is invalid")
    }

    #[test]
    fn a_recent_owner_signature_enrolls() {
        let enrollment = enrollment(&[DOMAIN]);
        for now in [NOW, NOW + MAX_ENROLLMENT_AGE_MS, NOW - MAX_CLOCK_SKEW_MS] {
            assert!(
                enrollment.verify(&signed_request(NOW), now).is_ok(),
                "{now}"
            );
        }
    }

    #[test]
    fn an_old_or_future_enrollment_is_refused() {
        let enrollment = enrollment(&[DOMAIN]);
        for now in [NOW + MAX_ENROLLMENT_AGE_MS + 1, NOW - MAX_CLOCK_SKEW_MS - 1] {
            assert_eq!(
                enrollment.verify(&signed_request(NOW), now).err(),
                Some(ApiError::StaleEnrollment)
            );
        }
    }

    #[test]
    fn a_signature_by_another_key_or_over_other_fields_is_refused() {
        let enrollment = enrollment(&[DOMAIN]);
        let invalid = Some(ApiError::InvalidOwnerEnrollmentSignature);
        let mut intruder = signed_request(NOW);
        intruder.owner_signature = sign(&SigningKey::from_bytes(&[4; 32]), DOMAIN, &intruder);
        assert_eq!(enrollment.verify(&intruder, NOW).err(), invalid);
        let mut other_key = signed_request(NOW);
        let secret = p256::SecretKey::from_slice(&[6; 32]).expect("test client key is invalid");
        other_key.client_public_key =
            hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
        assert_eq!(enrollment.verify(&other_key, NOW).err(), invalid);
        let mut other_time = signed_request(NOW);
        other_time.issued_at_ms += 1;
        assert_eq!(enrollment.verify(&other_time, NOW).err(), invalid);
    }

    #[test]
    fn a_signature_for_any_of_the_gateways_domains_enrolls() {
        let enrollment = enrollment(&["devnet.helius-rpc.com", DOMAIN]);
        for domain in ["devnet.helius-rpc.com", DOMAIN] {
            let mut request = signed_request(NOW);
            request.owner_signature = sign(&owner(), domain, &request);
            assert!(enrollment.verify(&request, NOW).is_ok(), "{domain}");
        }
    }

    #[test]
    fn a_signature_for_another_network_is_refused() {
        let mut mainnet = signed_request(NOW);
        mainnet.owner_signature = sign_for(&owner(), DOMAIN, Network::Mainnet, &mainnet);
        assert_eq!(
            enrollment(&[DOMAIN]).verify(&mainnet, NOW).err(),
            Some(ApiError::InvalidOwnerEnrollmentSignature)
        );
        let message = message(DOMAIN, Network::Mainnet, &mainnet).expect("formats");
        assert!(message.contains("\nChain ID: mainnet\n"), "{message}");
    }

    #[test]
    fn a_signature_for_another_domain_is_refused() {
        let mut elsewhere = signed_request(NOW);
        elsewhere.owner_signature = sign(&owner(), "wallet.example", &elsewhere);
        assert_eq!(
            enrollment(&[DOMAIN]).verify(&elsewhere, NOW).err(),
            Some(ApiError::InvalidOwnerEnrollmentSignature)
        );
    }

    #[test]
    fn malformed_requests_are_refused() {
        let enrollment = enrollment(&[DOMAIN]);
        let mut uppercase = signed_request(NOW);
        uppercase.client_public_key = uppercase.client_public_key.to_uppercase();
        assert!(enrollment.verify(&uppercase, NOW).is_err());
        let mut compressed = signed_request(NOW);
        compressed.client_public_key.truncate(66);
        assert!(enrollment.verify(&compressed, NOW).is_err());
        let mut multiline = signed_request(NOW);
        multiline.organization_id.push('\n');
        assert_eq!(
            enrollment.verify(&multiline, NOW).err(),
            Some(ApiError::InvalidEnrollmentRequest)
        );
    }

    #[test]
    fn the_message_matches_the_shared_test_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/wallet-enrollment.json"))
                .expect("the test vector parses");
        let mut enrollment = fixture["enrollment"].clone();
        let domain = enrollment["domain"].take();
        let network: Network =
            serde_json::from_value(enrollment["network"].take()).expect("the network parses");
        let object = enrollment
            .as_object_mut()
            .expect("the enrollment is an object");
        object.remove("domain");
        object.remove("network");
        object.insert("ownerSignature".to_owned(), "".into());
        let request: EnrollmentRequest =
            serde_json::from_value(enrollment).expect("the test vector is an enrollment");
        assert_eq!(
            message(
                domain.as_str().expect("the domain is a string"),
                network,
                &request
            ),
            fixture["message"].as_str().map(str::to_owned)
        );
    }
}
