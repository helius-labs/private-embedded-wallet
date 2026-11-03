import { fetchWithSignal, httpError, readBoundedText } from "../client/http.js";
import { createDefaultTransport, type TvcTransport } from "../client/transport.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex } from "../protocol/hex.js";
import type { SignedProverPolicyFile } from "../protocol/types.js";

/**
 * Where each network publishes its signed prover policy, as the Zolana SDK
 * pins it (`SignedTeePolicy.forNetwork`). The enclave image accepts the file
 * of the one network it was built for.
 */
export const PROVER_POLICY_URLS = Object.freeze({
  mainnet: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/mainnet.json",
  devnet: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/devnet.json",
});

export type TvcProverNetwork = keyof typeof PROVER_POLICY_URLS;

/** zolana-prover-tee's `MAX_SIGNED_POLICY_BYTES`. */
const MAX_POLICY_BYTES = 64n << 10n;
const LOWER_HEX = /^(?:[0-9a-f]{2})*$/;

/** A downloaded file and what the client reads from its payload. */
export type HeldProverPolicy = Readonly<{
  file: SignedProverPolicyFile;
  version: number;
  maxAgeSecs: number;
  /** Unix seconds. */
  expiresAt: number;
  fetchedAtMs: number;
}>;

/**
 * A network's signed prover policy file, which the client carries to the
 * enclave on every `Prove`. The enclave checks its signatures, network and
 * expiry; the client reads its payload only to know when to download it
 * again: once it is `max_age_secs` old, and after the prover lost its key or
 * the enclave refused it. A failed download keeps a file that has not
 * expired, and a file older than the one held is refused.
 */
export class TvcProverPolicy {
  readonly #url: URL;
  readonly #transport: TvcTransport | undefined;
  #held: HeldProverPolicy | undefined;
  #download: Promise<HeldProverPolicy> | undefined;

  constructor(url: string | URL, transport?: TvcTransport) {
    this.#url = new URL(url);
    this.#transport = transport;
  }

  /** The policy file `network` publishes. */
  static forNetwork(network: TvcProverNetwork, transport?: TvcTransport): TvcProverPolicy {
    if (!Object.hasOwn(PROVER_POLICY_URLS, network)) throw new TvcError("UnknownProverNetwork");
    return new TvcProverPolicy(PROVER_POLICY_URLS[network], transport);
  }

  /** The file in force, downloaded again once it is `max_age_secs` old. */
  current(signal?: AbortSignal): Promise<HeldProverPolicy> {
    const held = this.#held;
    if (held !== undefined && fresh(held, Date.now())) return Promise.resolve(held);
    this.#download ??= this.#refresh(signal).finally(() => {
      this.#download = undefined;
    });
    return this.#download;
  }

  /** Downloads the file again at the next call. */
  invalidate(): void {
    if (this.#held !== undefined) this.#held = { ...this.#held, fetchedAtMs: Number.NEGATIVE_INFINITY };
  }

  async #refresh(signal?: AbortSignal): Promise<HeldProverPolicy> {
    const held = this.#held;
    let next: HeldProverPolicy;
    try {
      next = readPolicy(await this.#fetch(signal));
    } catch (error) {
      if (held === undefined || expired(held, Date.now())) throw error;
      next = { ...held, fetchedAtMs: Date.now() };
    }
    if (held !== undefined) {
      if (next.version < held.version || (next.version === held.version && next.file.payload !== held.file.payload)) {
        throw new TvcError("ProverPolicyRollback");
      }
    }
    this.#held = Object.freeze(next);
    return this.#held;
  }

  async #fetch(signal?: AbortSignal): Promise<unknown> {
    const transport = this.#transport ?? createDefaultTransport();
    const response = await fetchWithSignal(transport, this.#url, { method: "GET", redirect: "error" }, signal);
    if (!response.ok) throw httpError(response, "ProverPolicyUnavailable");
    try {
      return JSON.parse(await readBoundedText(response, MAX_POLICY_BYTES, signal));
    } catch (error) {
      if (error instanceof TvcError && error.code === "ResponseTooLarge") throw error;
      throw new TvcError("ProverPolicyInvalid");
    }
  }
}

/** How long one attestation may serve further proofs under `held`. */
export function attestationReuseMs(held: HeldProverPolicy, nowMs: number): number {
  return Math.max(0, Math.min(held.maxAgeSecs * 1_000, held.expiresAt * 1_000 - nowMs));
}

function fresh(held: HeldProverPolicy, nowMs: number): boolean {
  const age = nowMs - held.fetchedAtMs;
  return age >= 0 && age < held.maxAgeSecs * 1_000 && !expired(held, nowMs);
}

function expired(held: HeldProverPolicy, nowMs: number): boolean {
  return nowMs >= held.expiresAt * 1_000;
}

/** The file's shape and the payload fields the client schedules by. */
function readPolicy(file: unknown): HeldProverPolicy {
  const invalid = (): TvcError => new TvcError("ProverPolicyInvalid");
  if (typeof file !== "object" || file === null || Array.isArray(file)) throw invalid();
  const { payload, signatures, ...rest } = file as Record<string, unknown>;
  if (Object.keys(rest).length > 0 || typeof payload !== "string" || !LOWER_HEX.test(payload)) throw invalid();
  if (
    !Array.isArray(signatures) ||
    !signatures.every(
      (entry: unknown) =>
        typeof entry === "object" &&
        entry !== null &&
        Object.keys(entry).length === 2 &&
        typeof (entry as Record<string, unknown>)["public_key"] === "string" &&
        typeof (entry as Record<string, unknown>)["signature"] === "string",
    )
  ) {
    throw invalid();
  }
  let approved: unknown;
  try {
    approved = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeLowerHex(payload)));
  } catch {
    throw invalid();
  }
  if (typeof approved !== "object" || approved === null) throw invalid();
  const { version, expires_at: expiresAt, policy } = approved as Record<string, unknown>;
  const maxAgeSecs =
    typeof policy === "object" && policy !== null ? (policy as Record<string, unknown>)["max_age_secs"] : undefined;
  if (![version, expiresAt, maxAgeSecs].every((value) => Number.isSafeInteger(value) && (value as number) >= 1)) {
    throw invalid();
  }
  if (Date.now() >= (expiresAt as number) * 1_000) throw new TvcError("ProverPolicyExpired");
  return {
    file: { payload, signatures: signatures as SignedProverPolicyFile["signatures"] },
    version: version as number,
    maxAgeSecs: maxAgeSecs as number,
    expiresAt: expiresAt as number,
    fetchedAtMs: Date.now(),
  };
}
