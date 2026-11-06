import type { API_VERSION } from "./constants.js";

/**
 * The Solana network a release, a descriptor and a running enclave serve.
 * Every check is equality with the network the checker expects.
 */
export type Network = "devnet" | "mainnet";

export type OperationKind = "Bootstrap" | "Decrypt" | "Derive" | "TransactionKeys" | "Prove";

export type HealthResponse = {
  status: "Healthy";
};

export type ServiceInfo = {
  version: number;
  network: Network;
  security_domain_id: string;
  release_id: string;
  manifest_digest: string;
  executable_digest: string;
  quorum_public_key: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  ephemeral_public_key: string;
  supported_operations: OperationKind[];
  /** Maximum UTF-8 bytes of the entire encrypted HTTP request envelope. */
  max_encrypted_request_bytes: string;
  max_encrypted_response_bytes: string;
  proof_type: string;
};

export type ReleasePolicy = {
  version: typeof API_VERSION;
  releaseId: string;
  network: Network;
  tvcApplicationId: string;
  securityDomainId: string;
  acceptedManifestDigests: readonly string[];
  acceptedExecutableDigests: readonly string[];
  quorumKeyId: string;
  quorumKeyEpoch: string;
  quorumPublicKey: string;
  allowedOperations: readonly OperationKind[];
  /** Maximum UTF-8 bytes of the entire encrypted HTTP request envelope. */
  maxEncryptedRequestBytes: number;
  maxEncryptedResponseBytes: number;
  turnkeyTrustRootId: string;
  turnkeyProofSchemaVersions: readonly string[];
  validFromMs: string;
  expiresAtMs: string;
  revocationEpoch: string;
};

/** A release authority's 64-byte raw low-S P-256 signature, hex. */
export type ReleaseAuthoritySignature = {
  keyId: string;
  signature: string;
};

export type SignedReleasePolicy = {
  policy: ReleasePolicy;
  authoritySetId: string;
  signatures: readonly ReleaseAuthoritySignature[];
};

export type ReleaseAuthorityKey = {
  keyId: string;
  publicKey: string;
};

export type PinnedReleaseAuthorities = {
  authoritySetId: string;
  threshold: number;
  keys: readonly ReleaseAuthorityKey[];
  /** Policies below the epoch are revoked. */
  minimumRevocationEpoch: string;
};

export type ClientGrant = {
  client_public_key: string;
  allowed_operations: OperationKind[];
};

/**
 * A short-lived grant, signed by the grant key the enclave is built with, that
 * one descriptor and client key may operate. It travels beside the ciphertext.
 */
export type WalletGrant = {
  version: typeof API_VERSION;
  descriptor_digest: string;
  client_key_id: string;
  project_id: string;
  issued_at_ms: string;
  expires_at_ms: string;
  signature: string;
};

/**
 * The gateway's grant that one client key may drive one Turnkey wallet's
 * operations, signed with the provisioning key the enclave is built with.
 */
export type WalletDescriptor = {
  version: typeof API_VERSION;
  security_domain_id: string;
  network: Network;
  turnkey_organization_id: string;
  turnkey_wallet_id: string;
  address: string;
  allowed_clients: ClientGrant[];
  /**
   * When the descriptor stops admitting its client key, in Unix ms. The
   * provisioning signature covers it; the enclave allows the protocol's clock
   * skew past it.
   */
  expires_at_ms: string;
  provisioning_signature: string;
};

/** Which cipher a ciphertext was sealed under. */
export type DecryptLabel = "Transfer" | "RingDeposit";

/**
 * One ciphertext to open with the wallet's viewing key. The answer is the
 * cipher's output, which the caller decodes; the enclave interprets nothing.
 */
export type DecryptItem = {
  ciphertext: string;
  /** Which of the wallet's viewing keys opens it; the enclave holds one. */
  viewing_public_key: string;
  transaction_viewing_public_key: string;
  salt: string;
  /** Zero for a ring deposit, which carries one envelope. */
  slot_index: string;
  label: DecryptLabel;
};

/** One value the protocol derives from the nullifier secret. */
export type DeriveItem =
  | { kind: "Nullifier"; utxo_hash: string; blinding: string }
  | { kind: "MergeDummyNullifier"; first_nullifier: string; slot_index: string }
  | { kind: "MergeOutputBlinding"; first_nullifier: string }
  | { kind: "MergePrivateTxBlinding"; first_nullifier: string }
  | { kind: "MergeOutputKey"; first_nullifier: string };

/** One per-transaction viewing key, named by the viewing key and the transaction's first nullifier. */
export type TransactionKeyItem = {
  viewing_public_key: string;
  first_nullifier: string;
};

/**
 * The prover's request body as the Zolana SDK encodes it, with `null` in every
 * nullifier secret slot the enclave is to fill (`proverRequestBody` and
 * `mergeProverRequestBody` from `@heliuslabs/spr/client`).
 */
export type ProverRequest = Readonly<Record<string, unknown>>;

export type BootstrapOperation = { type: "Bootstrap" };

export type DecryptOperation = { type: "Decrypt"; items: readonly DecryptItem[] };

export type DeriveOperation = { type: "Derive"; items: readonly DeriveItem[] };

export type TransactionKeysOperation = {
  type: "TransactionKeys";
  items: readonly TransactionKeyItem[];
};

/** One signed part of a prover policy file: the hex of a payload and the Ed25519 signatures over it. */
export type SignedProverPolicyPart = {
  payload: string;
  signatures: readonly { public_key: string; signature: string }[];
};

/**
 * A network's signed prover policy file (zolana `prover/tee/WIRE_CONTRACT.md`,
 * "Signed policy"), as downloaded: a release part that names the approved
 * measurements and a short-lived freshness part over it. The enclave verifies
 * it against the release signers its image pins.
 */
export type SignedProverPolicyFile = {
  release: SignedProverPolicyPart;
  freshness: SignedProverPolicyPart;
};

/**
 * The prover a `Prove` seals to: the route the client posts the sealed request
 * to (`/prove/<key>` below the prover URL, no query), the nonce the attestation
 * was requested with, the attestation as the prover answered it, and the
 * policy file.
 */
export type ProverSealing = {
  target: string;
  nonce: string;
  attestation: Readonly<Record<string, unknown>>;
  policy: SignedProverPolicyFile;
};

export type ProveOperation = { type: "Prove"; request: ProverRequest; prover: ProverSealing };

export type Operation =
  | BootstrapOperation
  | DecryptOperation
  | DeriveOperation
  | TransactionKeysOperation
  | ProveOperation;

/** The client key's 64-byte raw low-S P-256 signature over the request, hex. */
export type ClientAuthorization = {
  client_key_id: string;
  signature: string;
};

export type OperationRequest = {
  version: typeof API_VERSION;
  request_id: string;
  issued_at_ms: string;
  expires_at_ms: string;
  target_release_id: string;
  target_manifest_digest: string;
  target_executable_digest: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  wallet_descriptor: WalletDescriptor;
  sealed_seed: string | null;
  client_response_public_key: string;
  operation: Operation;
  authorization: ClientAuthorization;
};

/**
 * The derivation seed sealed to the Quorum key, as bootstrap returned it.
 * Presented on every later request; opaque to the client, not a secret, and
 * reproducible by another bootstrap of the same wallet.
 */
export type SealedSeed = {
  sealedSeed: string;
};

export type BootstrapResult = {
  type: "Bootstrap";
  solana_address: string;
  shielded_owner_hash: string;
  shielded_nullifier_public_key: string;
  shielded_viewing_public_key: string;
  /** The seed sealed to the Quorum key. No secret appears elsewhere. */
  sealed_seed: string;
  /** The Turnkey activity that signed the derivation message. */
  turnkey_activity_id: string;
};

/** One plaintext per item, in request order. */
export type DecryptResult = {
  type: "Decrypt";
  plaintexts: readonly string[];
};

/** One value per item, in request order. */
export type DeriveResult = {
  type: "Derive";
  values: readonly string[];
};

/** One per-transaction viewing secret per item, in request order. */
export type TransactionKeysResult = {
  type: "TransactionKeys";
  secrets: readonly string[];
};

/**
 * One encrypted prover request: post `ciphertext` to `target` with
 * `Spr-Tee: v1` and `Spr-Tee-Enc: enc`; `response_key` opens the answer and
 * nothing else.
 */
export type SealedProverRequest = {
  target: string;
  enc: string;
  ciphertext: string;
  response_key: string;
};

/** The completed request sealed to the attested prover. */
export type ProveResult = {
  type: "Prove";
  sealed: SealedProverRequest;
};

export type FailureStage = "Prover" | "TurnkeySigning";

export type FailureResult = {
  type: "Failure";
  operation: OperationKind;
  stage: FailureStage;
};

export type OperationResult =
  | BootstrapResult
  | DecryptResult
  | DeriveResult
  | TransactionKeysResult
  | ProveResult
  | FailureResult;

export const SERVICE_INFO_KEYS = [
  "version",
  "network",
  "security_domain_id",
  "release_id",
  "manifest_digest",
  "executable_digest",
  "quorum_public_key",
  "quorum_key_id",
  "quorum_key_epoch",
  "ephemeral_public_key",
  "supported_operations",
  "max_encrypted_request_bytes",
  "max_encrypted_response_bytes",
  "proof_type",
] as const;
