//! Wallet grants: a short-lived statement, signed by the grant key, that one
//! descriptor and client key may operate. The enclave refuses an operation
//! without a current grant, so an issuer revokes a client key by no longer
//! granting it.

use crate::constants::{API_VERSION, MAX_CLOCK_SKEW_MS, MAX_WALLET_GRANT_LIFETIME_MS};
use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::{descriptor_digest, wallet_grant_digest};
use crate::error::{ErrorCode, TvcError};
use crate::types::{WalletDescriptor, WalletGrant};

/// Signs `grant`, replacing any signature it carries.
pub fn sign_wallet_grant(
    mut grant: WalletGrant,
    secret: &[u8; 32],
) -> Result<WalletGrant, TvcError> {
    grant.signature = Vec::new();
    grant.signature = sign_p256_prehash(secret, &wallet_grant_digest(&grant)?)?.to_vec();
    Ok(grant)
}

/// Accepts a grant signed by `grant_public` for exactly this descriptor and
/// client key, issued no later than the clock allows, unexpired at `now_ms`,
/// and no longer lived than `MAX_WALLET_GRANT_LIFETIME_MS`.
pub fn verify_wallet_grant(
    grant: &WalletGrant,
    grant_public: &[u8],
    descriptor: &WalletDescriptor,
    client_key_id: &str,
    now_ms: u64,
) -> Result<(), TvcError> {
    let unauthorized = || TvcError::new(ErrorCode::UnauthorizedClient);
    if grant.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    verify_p256_prehash(grant_public, &wallet_grant_digest(grant)?, &grant.signature)
        .map_err(|_| unauthorized())?;
    if grant.descriptor_digest != descriptor_digest(descriptor)?
        || grant.client_key_id != client_key_id
    {
        return Err(unauthorized());
    }
    let lifetime = grant.expires_at_ms.checked_sub(grant.issued_at_ms);
    if !lifetime.is_some_and(|lifetime| lifetime <= MAX_WALLET_GRANT_LIFETIME_MS)
        || grant.issued_at_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || grant.expires_at_ms.saturating_add(MAX_CLOCK_SKEW_MS) < now_ms
    {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    use super::*;
    use crate::types::{ClientGrant, Network, OperationKind};

    const GRANT_SECRET: [u8; 32] = [6; 32];
    const NOW: u64 = 1_800_000_000_000;
    const CLIENT: &str = "spr-client-p256-00112233445566778899aabbccddeeff";

    fn grant_public() -> Vec<u8> {
        let secret = SecretKey::from_slice(&GRANT_SECRET).unwrap();
        secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn descriptor(wallet: &str) -> WalletDescriptor {
        WalletDescriptor {
            version: API_VERSION,
            security_domain_id: [1; 32],
            network: Network::Devnet,
            turnkey_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            turnkey_wallet_id: wallet.to_owned(),
            address: "11111111111111111111111111111111".to_owned(),
            allowed_clients: vec![ClientGrant {
                client_public_key: vec![4; 65],
                allowed_operations: vec![OperationKind::Bootstrap],
            }],
            provisioning_signature: vec![0; 64],
        }
    }

    fn grant(descriptor: &WalletDescriptor, issued_at_ms: u64, expires_at_ms: u64) -> WalletGrant {
        let unsigned = WalletGrant {
            version: API_VERSION,
            descriptor_digest: descriptor_digest(descriptor).unwrap(),
            client_key_id: CLIENT.to_owned(),
            project_id: "project-1".to_owned(),
            issued_at_ms,
            expires_at_ms,
            signature: Vec::new(),
        };
        sign_wallet_grant(unsigned, &GRANT_SECRET).unwrap()
    }

    fn verify(
        grant: &WalletGrant,
        descriptor: &WalletDescriptor,
        client: &str,
        now: u64,
    ) -> Option<ErrorCode> {
        verify_wallet_grant(grant, &grant_public(), descriptor, client, now)
            .err()
            .map(|error| error.code)
    }

    #[test]
    fn a_grant_admits_only_its_descriptor_and_client_key() {
        let mine = descriptor("wallet-a");
        let signed = grant(&mine, NOW, NOW + 900_000);
        assert_eq!(verify(&signed, &mine, CLIENT, NOW), None);
        assert_eq!(
            verify(&signed, &descriptor("wallet-b"), CLIENT, NOW),
            Some(ErrorCode::UnauthorizedClient)
        );
        assert_eq!(
            verify(
                &signed,
                &mine,
                "spr-client-p256-ffffffffffffffffffffffffffffffff",
                NOW
            ),
            Some(ErrorCode::UnauthorizedClient)
        );
    }

    #[test]
    fn a_grant_signed_by_another_key_or_altered_is_refused() {
        let mine = descriptor("wallet-a");
        let mut altered = grant(&mine, NOW, NOW + 900_000);
        altered.project_id = "project-2".to_owned();
        assert_eq!(
            verify(&altered, &mine, CLIENT, NOW),
            Some(ErrorCode::UnauthorizedClient)
        );
        let unsigned = WalletGrant {
            signature: Vec::new(),
            ..grant(&mine, NOW, NOW + 900_000)
        };
        let foreign = sign_wallet_grant(unsigned, &[7; 32]).unwrap();
        assert_eq!(
            verify(&foreign, &mine, CLIENT, NOW),
            Some(ErrorCode::UnauthorizedClient)
        );
    }

    #[test]
    fn a_grant_is_bounded_in_time() {
        let mine = descriptor("wallet-a");
        let expired = grant(&mine, NOW - 900_000, NOW - MAX_CLOCK_SKEW_MS - 1);
        assert_eq!(
            verify(&expired, &mine, CLIENT, NOW),
            Some(ErrorCode::ExpiredRequest)
        );
        let too_long = grant(&mine, NOW, NOW + MAX_WALLET_GRANT_LIFETIME_MS + 1);
        assert_eq!(
            verify(&too_long, &mine, CLIENT, NOW),
            Some(ErrorCode::ExpiredRequest)
        );
        let future = grant(&mine, NOW + MAX_CLOCK_SKEW_MS + 1, NOW + 900_000);
        assert_eq!(
            verify(&future, &mine, CLIENT, NOW),
            Some(ErrorCode::ExpiredRequest)
        );
        let inverted = grant(&mine, NOW, NOW - 1);
        assert_eq!(
            verify(&inverted, &mine, CLIENT, NOW),
            Some(ErrorCode::ExpiredRequest)
        );
    }
}
