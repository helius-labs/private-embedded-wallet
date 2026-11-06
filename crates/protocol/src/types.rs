//! Wire types: discovery, requests, results, sealed seed, release policy.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::encoding::{self, decimal_u64, hex};
use crate::error::{ErrorCode, TvcError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientAuthorizationScheme {
    #[serde(rename = "p256-sha256")]
    P256Sha256,
}

/// What a request asks for, as advertised by `/v1/info`, granted by a
/// descriptor, and named in the App Proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OperationKind {
    Bootstrap,
    Decrypt,
    Derive,
    TransactionKeys,
    Prove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HealthStatus {
    Healthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub status: HealthStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    pub version: u8,
    pub environment: Environment,
    #[serde(with = "hex")]
    pub security_domain_id: [u8; 32],
    pub release_id: String,
    #[serde(with = "hex")]
    pub manifest_digest: [u8; 32],
    #[serde(with = "hex")]
    pub executable_digest: [u8; 32],
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex")]
    pub ephemeral_public_key: Vec<u8>,
    pub supported_operations: Vec<OperationKind>,
    #[serde(with = "decimal_u64")]
    pub max_encrypted_request_bytes: u64,
    #[serde(with = "decimal_u64")]
    pub max_encrypted_response_bytes: u64,
    pub proof_type: String,
    #[serde(with = "hex")]
    pub boot_proof_lookup_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrant {
    #[serde(with = "hex")]
    pub client_public_key: Vec<u8>,
    pub allowed_operations: Vec<OperationKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletDescriptor {
    pub version: u8,
    #[serde(with = "hex")]
    pub security_domain_id: [u8; 32],
    pub environment: Environment,
    pub turnkey_organization_id: String,
    pub turnkey_wallet_id: String,
    pub address: String,
    pub allowed_clients: Vec<ClientGrant>,
    #[serde(with = "hex")]
    pub provisioning_signature: Vec<u8>,
}

impl WalletDescriptor {
    pub fn wallet_id(&self) -> String {
        format!("wallet-{}", self.turnkey_wallet_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthorization {
    pub client_key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

/// Which cipher a ciphertext was sealed under: the transfer cipher over a
/// numbered output slot, or the ring-deposit envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DecryptLabel {
    Transfer,
    RingDeposit,
}

/// One ciphertext to open with the wallet's viewing key. The result is the
/// cipher's output, which the client decodes; the enclave interprets nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptItem {
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
    /// Which of the wallet's viewing keys opens it; this wallet holds one.
    #[serde(with = "hex")]
    pub viewing_public_key: Vec<u8>,
    #[serde(with = "hex")]
    pub transaction_viewing_public_key: Vec<u8>,
    #[serde(with = "hex")]
    pub salt: Vec<u8>,
    /// Zero for a ring deposit, which carries one envelope.
    #[serde(with = "decimal_u64")]
    pub slot_index: u64,
    pub label: DecryptLabel,
}

/// One value the protocol derives from the nullifier secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum DeriveItem {
    /// The nullifier that spends the UTXO with this commitment and blinding.
    Nullifier {
        #[serde(with = "hex")]
        utxo_hash: [u8; 32],
        #[serde(with = "hex")]
        blinding: [u8; 32],
    },
    /// The published nullifier of a padded merge slot.
    MergeDummyNullifier {
        #[serde(with = "hex")]
        first_nullifier: [u8; 32],
        #[serde(with = "decimal_u64")]
        slot_index: u64,
    },
    /// The blinding of a merge's output.
    MergeOutputBlinding {
        #[serde(with = "hex")]
        first_nullifier: [u8; 32],
    },
    /// The private-transaction hash blinding of a merge.
    MergePrivateTxBlinding {
        #[serde(with = "hex")]
        first_nullifier: [u8; 32],
    },
    /// The key of a merge's output ciphertext.
    MergeOutputKey {
        #[serde(with = "hex")]
        first_nullifier: [u8; 32],
    },
}

/// One per-transaction viewing key, derived from a viewing key and the
/// transaction's first nullifier. The derivation is one way, so the secret
/// returned opens that transaction and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionKeyItem {
    #[serde(with = "hex")]
    pub viewing_public_key: Vec<u8>,
    #[serde(with = "hex")]
    pub first_nullifier: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Operation {
    /// Derives the shielded identity and seals it to the Quorum key. The client
    /// stores the opaque blob and presents it on every later request.
    Bootstrap,
    /// Opens ciphertexts with the wallet's viewing key.
    Decrypt { items: Vec<DecryptItem> },
    /// Derives nullifiers and merge values from the nullifier secret.
    Derive { items: Vec<DeriveItem> },
    /// Derives per-transaction viewing keys.
    TransactionKeys { items: Vec<TransactionKeyItem> },
    /// Completes a prover request and seals it to the attested prover
    /// `prover` names. The body is the Zolana SDK's prover request with
    /// `null` in every nullifier secret slot the enclave is to fill; the
    /// enclave fills those slots and changes nothing else.
    Prove {
        request: serde_json::Value,
        prover: Box<ProverSealing>,
    },
}

/// The prover a `Prove` seals to: where the client posts the sealed request
/// and the evidence that the key it is sealed to sits in a measured prover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProverSealing {
    /// The path the client posts the sealed request to: `/prove/<key>` under
    /// any prefix, without a query. The encryption binds it.
    pub target: String,
    /// The nonce the attestation was requested with.
    #[serde(with = "hex")]
    pub nonce: [u8; 32],
    /// The prover's answer to `GET /attestation`, as received.
    pub attestation: serde_json::Value,
    /// The network's signed prover policy file (zolana
    /// `prover/tee/WIRE_CONTRACT.md`, "Signed policy"), as downloaded. The
    /// enclave verifies it against the signers its image pins.
    pub policy: serde_json::Value,
}

impl Operation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Bootstrap => OperationKind::Bootstrap,
            Self::Decrypt { .. } => OperationKind::Decrypt,
            Self::Derive { .. } => OperationKind::Derive,
            Self::TransactionKeys { .. } => OperationKind::TransactionKeys,
            Self::Prove { .. } => OperationKind::Prove,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    #[serde(with = "decimal_u64")]
    pub issued_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    pub target_release_id: String,
    #[serde(with = "hex")]
    pub target_manifest_digest: [u8; 32],
    #[serde(with = "hex")]
    pub target_executable_digest: [u8; 32],
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    pub wallet_descriptor: WalletDescriptor,
    #[serde(with = "hex")]
    pub sealed_seed: Option<Vec<u8>>,
    #[serde(with = "hex")]
    pub client_response_public_key: Vec<u8>,
    pub operation: Operation,
    pub authorization: ClientAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRequest {
    pub version: u8,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
    /// The grant admitting the request's descriptor and client key, outside
    /// the ciphertext so a gateway in front of the enclave can check it too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_grant: Option<WalletGrant>,
}

/// A short-lived grant, signed by the grant key the enclave is built with,
/// that one descriptor and client key may operate. `project_id` names the
/// account the issuer attributes the wallet to; the enclave does not read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletGrant {
    pub version: u8,
    #[serde(with = "hex")]
    pub descriptor_digest: [u8; 32],
    pub client_key_id: String,
    pub project_id: String,
    #[serde(with = "decimal_u64")]
    pub issued_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSeed {
    pub version: u8,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub wallet_id_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProof {
    pub scheme: String,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
    pub proof_payload: String,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

/// Connection challenge encrypted to the QOS Quorum encryption subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingChallenge {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex")]
    pub challenge: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingRequest {
    pub version: u8,
    #[serde(with = "hex")]
    pub encrypted_challenge: Vec<u8>,
}

/// Proof that the running enclave decrypted with the Quorum key and signed the
/// exact challenge bytes with its Ephemeral signing subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingResponse {
    pub version: u8,
    pub tvc_app_proof: AppProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedResponse {
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    #[serde(with = "hex")]
    pub encrypted_result: Vec<u8>,
    pub tvc_app_proof: AppProof,
}

/// The typed Turnkey proof fields returned by `turnkey_client`. Their policy
/// evidence is cryptographically valid but unbound to our intent until
/// Turnkey publishes a decision-context binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyAppProof {
    pub scheme: String,
    pub public_key: String,
    pub proof_payload: String,
    pub signature: String,
}

/// Coarse, non-secret failure marker, returned only inside the encrypted result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureStage {
    /// The prover's attestation or policy was refused.
    Prover,
    /// Turnkey declined to sign the derivation message.
    TurnkeySigning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum OperationResult {
    Bootstrap {
        solana_address: String,
        #[serde(with = "hex")]
        shielded_owner_hash: [u8; 32],
        #[serde(with = "hex")]
        shielded_nullifier_public_key: [u8; 32],
        #[serde(with = "hex")]
        shielded_viewing_public_key: Vec<u8>,
        /// The derivation seed sealed to the Quorum key: presented on every
        /// later operation, reproducible by another bootstrap, never a secret
        /// to the client. No secret appears elsewhere in this result.
        #[serde(with = "hex")]
        sealed_seed: Vec<u8>,
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyAppProof>,
    },
    /// One plaintext per item, in request order.
    Decrypt {
        #[serde(with = "hex")]
        plaintexts: Vec<Vec<u8>>,
    },
    /// One value per item, in request order.
    Derive {
        #[serde(with = "hex")]
        values: Vec<[u8; 32]>,
    },
    /// One per-transaction viewing secret per item, in request order.
    TransactionKeys {
        #[serde(with = "hex")]
        secrets: Vec<[u8; 32]>,
    },
    /// The completed request sealed to the attested prover, for the client
    /// to post to `target`, and the key that opens the prover's answer.
    Prove { sealed: SealedProverRequest },
    Failure {
        operation: OperationKind,
        stage: FailureStage,
    },
}

/// One prover request under the encrypted prover wire contract: `ciphertext`
/// is the body of `POST target` with `Spr-Tee: v1` and `Spr-Tee-Enc:
/// enc`, and `response_key` opens the answer. The key is an HPKE export, so it
/// opens no request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedProverRequest {
    pub target: String,
    #[serde(with = "hex")]
    pub enc: [u8; 32],
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    pub response_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProofPayload {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    #[serde(with = "hex")]
    pub request_digest: [u8; 32],
    #[serde(with = "hex")]
    pub result_digest: [u8; 32],
    pub operation: OperationKind,
    #[serde(with = "hex")]
    pub sealed_seed_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePolicy {
    pub version: u8,
    pub release_id: String,
    pub environment: Environment,
    pub tvc_application_id: String,
    #[serde(with = "hex")]
    pub security_domain_id: [u8; 32],
    pub accepted_manifest_digests: Vec<String>,
    pub accepted_executable_digests: Vec<String>,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub allowed_operations: Vec<OperationKind>,
    pub max_encrypted_request_bytes: u32,
    pub max_encrypted_response_bytes: u32,
    pub turnkey_trust_root_id: String,
    pub turnkey_proof_schema_versions: Vec<String>,
    #[serde(with = "decimal_u64")]
    pub valid_from_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthoritySignature {
    pub key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleasePolicy {
    pub policy: ReleasePolicy,
    pub authority_set_id: String,
    pub signatures: Vec<ReleaseAuthoritySignature>,
}

pub fn parse_operation_request(json: &str) -> Result<OperationRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_encrypted_request(json: &str) -> Result<EncryptedRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_request(json: &str) -> Result<QosPingRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_challenge(json: &str) -> Result<QosPingChallenge, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn reject_production_environment(environment: Environment) -> Result<(), TvcError> {
    match environment {
        Environment::Development => Ok(()),
        Environment::Production => Err(TvcError::new(ErrorCode::ProductionClaimRejected)),
    }
}
