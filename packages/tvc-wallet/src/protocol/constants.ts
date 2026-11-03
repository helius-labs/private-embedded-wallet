export const API_VERSION = 1;
export const TVC_APP_PROOF_TYPE = "zolana.tvc.wallet_operation.v1";
export const EXPECTED_TURNKEY_TRUST_ROOT_ID = "aws-nitro-root-g1";
export const TVC_APP_PROOF_SCHEME = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
export const TVC_QOS_PING_PROOF_TYPE = "zolana.tvc.qos_ping.v1";
export const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;

export const REQUEST_DIGEST_DOMAIN = "ZOLANA_TVC_REQUEST_V1";
export const CLIENT_AUTH_DOMAIN = "ZOLANA_TVC_CLIENT_AUTH_V1";
export const RESULT_DIGEST_DOMAIN = "ZOLANA_TVC_RESULT_V1";
export const WALLET_ID_HASH_DOMAIN = "ZOLANA_TVC_WALLET_ID_V1";
export const REQUEST_ID_HASH_DOMAIN = "ZOLANA_TVC_REQUEST_ID_V1";
export const SEALED_SEED_DIGEST_DOMAIN = "ZOLANA_TVC_SEALED_SEED_DIGEST_V1";
export const RELEASE_POLICY_DOMAIN = "ZOLANA_TVC_RELEASE_POLICY_V1";
export const PROVISIONING_AUTH_DOMAIN = "ZOLANA_TVC_PROVISIONING_AUTH_V1";
export const WALLET_GRANT_DOMAIN = "ZOLANA_TVC_WALLET_GRANT_V1";

export const MAX_REQUEST_AGE_MS = 300_000n;
export const MAX_CLOCK_SKEW_MS = 60_000n;

export const QOS_P256_PUBLIC_LEN = 130;
export const SEC1_UNCOMPRESSED_LEN = 65;
export const RAW_P256_SIGNATURE_LEN = 64;
export const AES_GCM_NONCE_LEN = 12;
export const AES_GCM_TAG_LEN = 16;
export const SHA256_LEN = 32;
export const SHA384_LEN = 48;
export const QOS_ENCRYPTION_HMAC_MESSAGE = "qos_encryption_hmac_message";
