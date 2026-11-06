import type { FailureStage, OperationKind } from "./types.js";

export class SprEmbeddedWalletError extends Error {
  readonly code: string;

  /**
   * `code` is the stable protocol identifier callers compare against; `detail`
   * is optional human-readable context, which may include untrusted text and
   * therefore never becomes part of `code`.
   */
  constructor(code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "SprEmbeddedWalletError";
    this.code = code;
  }
}

/** HTTP failures retain rate-limit information without returning an untrusted response body. */
export class SprEmbeddedWalletHttpError extends SprEmbeddedWalletError {
  constructor(code: string, readonly status: number, readonly retryAfter: string | null) {
    super(code, `HTTP ${status}`);
    this.name = "SprEmbeddedWalletHttpError";
  }
}

/**
 * An operation that ran and failed at a named stage, which the enclave answers
 * inside the encrypted result: `Prover` when it refused the prover's policy or
 * attestation, `TurnkeySigning` when Turnkey declined to sign the bootstrap
 * message.
 */
export class SprEmbeddedWalletOperationError extends SprEmbeddedWalletError {
  constructor(readonly operation: OperationKind, readonly stage: FailureStage) {
    super("OperationFailed", stage);
    this.name = "SprEmbeddedWalletOperationError";
  }
}
