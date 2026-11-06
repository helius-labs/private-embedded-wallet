import { requestScope, type SprEmbeddedWalletRequestOptions } from "../client/request.js";
import { decodeDecimalU64 } from "../protocol/decimal.js";
import { sealedSeedDigest } from "../protocol/digest.js";
import { SprEmbeddedWalletError, SprEmbeddedWalletOperationError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type {
  SealedSeed,
  DecryptOperation,
  FailureStage,
  DeriveOperation,
  Operation,
  OperationResult,
  ProveOperation,
  TransactionKeysOperation,
} from "../protocol/types.js";
import { assertExactObjectKeys } from "../client/http.js";
import { isProveCircuit, MAX_PROVE_INPUTS, proverTarget, provingKeyName } from "./prover.js";
import {
  executeOperationEnvelope,
  type OperationExecutionContext,
} from "../client/operation-executor.js";

/** Mirrors `crates/protocol/src/constants.rs`; rejecting here saves a round trip. */
export const MAX_ITEMS_PER_BATCH = 256;

const U32_MAX = 0xffff_ffffn;
const U8_MAX = 0xffn;
const SALT_BYTES = 16;
/** A tagged X25519 viewing key, `0x04 || u`. */
const VIEWING_PUBLIC_KEY_BYTES = 33;

// A Record so the compiler still requires an entry per result variant; the
// lookup uses Object.hasOwn because `result.type` is server-controlled and a
// bare index would resolve inherited names such as "toString".
const RESULT_KEYS: Record<OperationResult["type"], readonly string[]> = {
  Bootstrap: [
    "type",
    "solana_address",
    "shielded_owner_hash",
    "shielded_nullifier_public_key",
    "shielded_viewing_public_key",
    "sealed_seed",
    "turnkey_activity_id",
  ],
  Decrypt: ["type", "plaintexts"],
  Derive: ["type", "values"],
  TransactionKeys: ["type", "secrets"],
  Prove: ["type", "sealed"],
  Failure: ["type", "operation", "stage"],
};

type ResultFor<TOperation extends Operation> = Extract<
  OperationResult,
  { type: TOperation["type"] }
>;

function checkBatch(items: readonly unknown[]): void {
  if (items.length === 0) throw new SprEmbeddedWalletError("EmptyBatch");
  if (items.length > MAX_ITEMS_PER_BATCH) throw new SprEmbeddedWalletError("BatchTooLarge");
}

/** Checks a `Decrypt` request's bounds and encodings before it is signed. */
export function checkDecrypt(operation: DecryptOperation): DecryptOperation {
  checkBatch(operation.items);
  for (const item of operation.items) {
    requireHex(item.ciphertext);
    requireHex(item.viewing_public_key, VIEWING_PUBLIC_KEY_BYTES);
    requireHex(item.transaction_viewing_public_key, VIEWING_PUBLIC_KEY_BYTES);
    requireHex(item.salt, SALT_BYTES);
    const slot = decodeDecimalU64(item.slot_index);
    if (slot > U32_MAX || (item.label === "RingDeposit" && slot !== 0n)) {
      throw new SprEmbeddedWalletError("InvalidSlotIndex");
    }
    if (item.label !== "Transfer" && item.label !== "RingDeposit") {
      throw new SprEmbeddedWalletError("InvalidCanonicalJson");
    }
  }
  return operation;
}

/** Checks a `Derive` request's bounds and encodings before it is signed. */
export function checkDerive(operation: DeriveOperation): DeriveOperation {
  checkBatch(operation.items);
  for (const item of operation.items) {
    switch (item.kind) {
      case "Nullifier":
        requireHex(item.utxo_hash, 32);
        requireHex(item.blinding, 32);
        break;
      case "MergeDummyNullifier":
        requireHex(item.first_nullifier, 32);
        if (decodeDecimalU64(item.slot_index) > U8_MAX) throw new SprEmbeddedWalletError("InvalidSlotIndex");
        break;
      case "MergeOutputBlinding":
      case "MergePrivateTxBlinding":
      case "MergeOutputKey":
        requireHex(item.first_nullifier, 32);
        break;
    }
  }
  return operation;
}

/** Checks a `TransactionKeys` request's bounds and encodings before it is signed. */
export function checkTransactionKeys(
  operation: TransactionKeysOperation,
): TransactionKeysOperation {
  checkBatch(operation.items);
  for (const item of operation.items) {
    requireHex(item.viewing_public_key, VIEWING_PUBLIC_KEY_BYTES);
    requireHex(item.first_nullifier, 32);
  }
  return operation;
}

const SEALING_KEYS = ["target", "nonce", "attestation", "policy"] as const;
const SIGNED_POLICY_KEYS = ["release", "freshness"] as const;
const SIGNED_PART_KEYS = ["payload", "signatures"] as const;
const SEALED_KEYS = ["target", "enc", "ciphertext", "response_key"] as const;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Checks a `Prove` request names a circuit the enclave completes and leaves at
 * least one slot for it to fill, and that it seals to its proving key's route;
 * the body's shape is otherwise the prover's.
 */
export function checkProve(operation: ProveOperation): ProveOperation {
  const sealing = operation.prover;
  assertExactObjectKeys(sealing, SEALING_KEYS, "InvalidProverRequest");
  assertExactObjectKeys(sealing.policy, SIGNED_POLICY_KEYS, "InvalidProverRequest");
  for (const part of [sealing.policy.release, sealing.policy.freshness]) {
    assertExactObjectKeys(part, SIGNED_PART_KEYS, "InvalidProverRequest");
    if (typeof part.payload !== "string" || !Array.isArray(part.signatures)) {
      throw new SprEmbeddedWalletError("InvalidProverRequest");
    }
  }
  requireHex(sealing.nonce, 32);
  if (!isObject(sealing.attestation)) throw new SprEmbeddedWalletError("InvalidProverRequest");
  const body = operation.request;
  const circuit = body["circuitType"];
  if (!isProveCircuit(circuit)) {
    throw new SprEmbeddedWalletError("InvalidProverRequest");
  }
  const inputs = body["inputs"];
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > MAX_PROVE_INPUTS) {
    throw new SprEmbeddedWalletError("InvalidProverRequest");
  }
  const open =
    circuit === "merge" || circuit === "merge-ring"
      ? body["userNullifierSecret"] === null
      : inputs.some(
          (input: unknown) =>
            typeof input === "object" &&
            input !== null &&
            (input as Record<string, unknown>)["nullifierSecret"] === null,
        );
  if (!open) throw new SprEmbeddedWalletError("InvalidProverRequest");
  if (sealing.target !== proverTarget(provingKeyName(body))) {
    throw new SprEmbeddedWalletError("InvalidProverRequest", "target is not the request's proving key route");
  }
  return operation;
}

function checkHexList(values: unknown, count: number, bytes?: number): asserts values is string[] {
  if (!Array.isArray(values) || values.length !== count) {
    throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
  }
  for (const value of values) requireHex(value, bytes);
}

const FAILURE_STAGES: readonly string[] = ["Prover", "TurnkeySigning"] satisfies FailureStage[];

function checkResult<TOperation extends Operation>(
  result: OperationResult,
  operation: TOperation,
  proofSeedDigest: string,
): asserts result is ResultFor<TOperation> {
  const keys = Object.hasOwn(RESULT_KEYS, result.type) ? RESULT_KEYS[result.type] : undefined;
  if (!keys) throw new SprEmbeddedWalletError("UnsupportedVersion");
  assertExactObjectKeys(result, keys, "InvalidCanonicalJson");
  if (result.type === "Failure") {
    if (result.operation !== operation.type) {
      throw new SprEmbeddedWalletError(
        "ReleaseBindingMismatch",
        `failure names ${result.operation}, asked for ${operation.type}`,
      );
    }
    if (!FAILURE_STAGES.includes(result.stage)) throw new SprEmbeddedWalletError("UnsupportedVersion");
    throw new SprEmbeddedWalletOperationError(result.operation, result.stage);
  }
  if (result.type !== operation.type) {
    throw new SprEmbeddedWalletError("ReleaseBindingMismatch", `result is ${result.type}, asked for ${operation.type}`);
  }

  switch (result.type) {
    case "Bootstrap": {
      requireHex(result.shielded_owner_hash, 32);
      requireHex(result.shielded_nullifier_public_key, 32);
      requireHex(result.shielded_viewing_public_key, VIEWING_PUBLIC_KEY_BYTES);
      if (!result.solana_address) throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
      // The sealed blob must be the one the App Proof committed to; otherwise a
      // response could carry a different seed than the one that was signed.
      const digest = encodeLowerHex(sealedSeedDigest(requireHex(result.sealed_seed)));
      if (digest !== proofSeedDigest) throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
      return;
    }
    case "Decrypt": {
      if (operation.type !== "Decrypt") throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
      checkHexList(result.plaintexts, operation.items.length);
      return;
    }
    case "Derive": {
      if (operation.type !== "Derive") throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
      checkHexList(result.values, operation.items.length, 32);
      return;
    }
    case "TransactionKeys": {
      if (operation.type !== "TransactionKeys") throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
      checkHexList(result.secrets, operation.items.length, 32);
      return;
    }
    case "Prove": {
      if (operation.type !== "Prove") throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
      assertExactObjectKeys(result.sealed, SEALED_KEYS, "InvalidCanonicalJson");
      if (result.sealed.target !== operation.prover.target) {
        throw new SprEmbeddedWalletError("ReleaseBindingMismatch", "sealed for another target");
      }
      requireHex(result.sealed.enc, 32);
      requireHex(result.sealed.response_key, 32);
      if (requireHex(result.sealed.ciphertext).length === 0) {
        throw new SprEmbeddedWalletError("ReleaseBindingMismatch", "empty sealed request");
      }
      return;
    }
  }
}

/** Aborting the signal abandons the HTTP exchange; the enclave keeps no state for it. */
export type OperationOptions = SprEmbeddedWalletRequestOptions;

/**
 * Runs one operation through the encrypted envelope and returns its checked
 * result. When a sealed seed is presented, the App Proof must name exactly
 * that seed, or the answer could have come from different keys than the ones
 * asked about.
 */
export async function executeOperation<TOperation extends Operation>(
  context: OperationExecutionContext,
  operation: TOperation,
  sealedSeed?: SealedSeed,
  options?: OperationOptions,
): Promise<ResultFor<TOperation>> {
  const scope = requestScope(options, context.requestTimeoutMs);
  try {
    scope.signal.throwIfAborted();
    const envelope = await executeOperationEnvelope(context, operation, sealedSeed, scope.signal);
    if (
      sealedSeed &&
      envelope.sealedSeedDigest !== encodeLowerHex(sealedSeedDigest(decodeLowerHex(sealedSeed.sealedSeed)))
    ) {
      throw new SprEmbeddedWalletError("ReleaseBindingMismatch", "proof names another sealed seed");
    }
    const result = parseStrictJson<OperationResult>(envelope.plaintext);
    checkResult(result, operation, envelope.sealedSeedDigest);
    return result;
  } finally { scope.dispose(); }
}
