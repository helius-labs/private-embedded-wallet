//! Domain separators and protocol limits.

pub const API_VERSION: u8 = 1;
pub const TVC_APP_PROOF_TYPE: &str = "zolana.tvc.wallet_operation.v1";
pub const TVC_APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
pub const TVC_QOS_PING_PROOF_TYPE: &str = "zolana.tvc.qos_ping.v1";
pub const EXPECTED_TURNKEY_TRUST_ROOT_ID: &str = "aws-nitro-root-g1";
/// A client key's ID is this prefix and the first 16 bytes of the SHA-256 of
/// its SEC1 encoding, in hex.
pub const CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";

/// What a client key signs is the UTF-8 text `<CLIENT_AUTH_DOMAIN>:<request
/// digest in lowercase hex>`, so a key that signs only text, such as a Turnkey
/// session key through `signWithApiKey`, can sign it.
pub const CLIENT_AUTH_DOMAIN: &str = "spr-tvc-client-auth-v1";
pub const PROVISIONING_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_PROVISIONING_AUTH_V1";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_REQUEST_V1";
pub const RESULT_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_RESULT_V1";
pub const SEALED_SEED_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_SEALED_SEED_DIGEST_V1";
pub const WALLET_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_WALLET_ID_V1";
pub const WALLET_BINDING_DOMAIN: &[u8] = b"ZOLANA_TVC_WALLET_BINDING_V1";
pub const REQUEST_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_REQUEST_ID_V1";
pub const RELEASE_POLICY_DOMAIN: &[u8] = b"ZOLANA_TVC_RELEASE_POLICY_V1";
pub const WALLET_GRANT_DOMAIN: &[u8] = b"ZOLANA_TVC_WALLET_GRANT_V1";

pub const MAX_REQUEST_AGE_MS: u64 = 300_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;
/// Longest a wallet grant may live, so revoking a client key takes effect
/// within this window whoever issued the grant.
pub const MAX_WALLET_GRANT_LIFETIME_MS: u64 = 3_600_000;
/// Maximum bytes of the entire serialized encrypted HTTP request envelope.
pub const MAX_ENCRYPTED_REQUEST_BYTES: u64 = 262_144;
pub const MAX_ENCRYPTED_RESPONSE_BYTES: u64 = 262_144;

/// Caps the items of one `Decrypt`, `Derive`, or `TransactionKeys` batch. The
/// envelope limit bounds bytes, not work; this bounds work, and clients page
/// against it.
pub const MAX_ITEMS_PER_BATCH: u64 = 256;
/// Caps the input slots of one `Prove` request; the largest installed circuit,
/// `merge_52_1`, takes 52.
pub const MAX_PROVE_INPUTS: usize = 52;
/// Caps the path a sealed prover request is bound to.
pub const MAX_PROVER_TARGET_LEN: usize = 256;

pub const SEC1_UNCOMPRESSED_LEN: usize = 65;
pub const QOS_P256_PUBLIC_LEN: usize = 130;
pub const RAW_P256_SIGNATURE_LEN: usize = 64;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const AES_GCM_TAG_LEN: usize = 16;

pub const QOS_ENCRYPTION_HMAC_MESSAGE: &[u8] = b"qos_encryption_hmac_message";
