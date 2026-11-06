import { fetchWithSignal, httpError, readBoundedText } from "../client/http.js";
import { awaitWithSignal } from "../client/request.js";
import { createDefaultTransport, type TvcTransport } from "../client/transport.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex } from "../protocol/hex.js";
import { requireNetwork } from "../protocol/network.js";
import type { Network, SignedProverPolicyFile, SignedProverPolicyPart } from "../protocol/types.js";

/**
 * Where each network publishes its signed prover policy, as the Zolana SDK
 * pins it (`SignedTeePolicy.forNetwork`). The enclave image accepts the file
 * of the one network it was built for.
 */
export const PROVER_POLICY_URLS: Readonly<Record<Network, string>> = Object.freeze({
  mainnet: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/mainnet.json",
  devnet: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/devnet.json",
});

/** zolana-prover-tee's `MAX_SIGNED_POLICY_BYTES`. */
const MAX_POLICY_BYTES = 64n << 10n;
const LOWER_HEX = /^(?:[0-9a-f]{2})*$/;

/** A downloaded file and what the client reads from its payloads. */
export type HeldProverPolicy = Readonly<{
  file: SignedProverPolicyFile;
  /** The release version. */
  version: number;
  maxAgeSecs: number;
  /** When the freshness part was issued, Unix seconds. */
  issuedAt: number;
  /** The earlier of the release and freshness expiries, Unix seconds. */
  expiresAt: number;
  fetchedAtMs: number;
}>;

/** One download of the file, shared by every caller waiting for it. */
type Download = {
  readonly controller: AbortController;
  readonly promise: Promise<HeldProverPolicy>;
  waiters: number;
};

/**
 * A network's signed prover policy file, which the client carries to the
 * enclave on every `Prove`. The enclave checks its signatures, network and
 * expiries; the client reads its payloads only to know when to download it
 * again: once it is `max_age_secs` old, and after the prover lost its key or
 * the enclave refused it. A failed download keeps a file until either part
 * expires.
 */
export class TvcProverPolicy {
  readonly #url: URL;
  readonly #transport: TvcTransport | undefined;
  #held: HeldProverPolicy | undefined;
  #download: Download | undefined;

  constructor(url: string | URL, transport?: TvcTransport) {
    this.#url = new URL(url);
    this.#transport = transport;
  }

  /** The policy file `network` publishes. */
  static forNetwork(network: Network, transport?: TvcTransport): TvcProverPolicy {
    return new TvcProverPolicy(PROVER_POLICY_URLS[requireNetwork(network)], transport);
  }

  /**
   * The file in force, downloaded again once it is `max_age_secs` old.
   * Concurrent callers share one download; `signal` ends this caller's wait,
   * and the download stops once no caller waits for it.
   */
  async current(signal?: AbortSignal): Promise<HeldProverPolicy> {
    signal?.throwIfAborted();
    const held = this.#held;
    if (held !== undefined && fresh(held, Date.now())) return held;
    const download = (this.#download ??= this.#start());
    download.waiters += 1;
    try {
      return await awaitWithSignal(download.promise, signal);
    } finally {
      download.waiters -= 1;
      if (download.waiters === 0 && this.#download === download) {
        this.#download = undefined;
        download.controller.abort(signal?.reason);
      }
    }
  }

  /** Downloads the file again at the next call. */
  invalidate(): void {
    if (this.#held !== undefined) this.#held = { ...this.#held, fetchedAtMs: Number.NEGATIVE_INFINITY };
  }

  #start(): Download {
    const controller = new AbortController();
    const download: Download = {
      controller,
      waiters: 0,
      promise: this.#refresh(controller.signal).finally(() => {
        if (this.#download === download) this.#download = undefined;
      }),
    };
    return download;
  }

  async #refresh(signal: AbortSignal): Promise<HeldProverPolicy> {
    const held = this.#held;
    let next: HeldProverPolicy;
    try {
      next = readPolicy(await this.#fetch(signal));
      // A download every caller abandoned does not replace the held file.
      signal.throwIfAborted();
    } catch (error) {
      if (signal.aborted || held === undefined || expired(held, Date.now())) throw error;
      next = { ...held, fetchedAtMs: Date.now() };
    }
    this.#held = Object.freeze(next);
    return this.#held;
  }

  async #fetch(signal: AbortSignal): Promise<unknown> {
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
  if (!isRecord(file)) throw invalid();
  const { release, freshness, ...rest } = file;
  if (Object.keys(rest).length > 0) throw invalid();
  const releasePart = readPart(release, invalid);
  const freshnessPart = readPart(freshness, invalid);
  const approved = readPayload(releasePart.payload, invalid);
  const fresh = readPayload(freshnessPart.payload, invalid);
  const { version, expires_at: releaseExpiresAt, policy } = approved;
  const maxAgeSecs = isRecord(policy) ? policy["max_age_secs"] : undefined;
  const { issued_at: issuedAt, expires_at: freshUntil } = fresh;
  if (![version, releaseExpiresAt, maxAgeSecs, freshUntil].every((value) => isInteger(value) && (value as number) >= 1)) {
    throw invalid();
  }
  if (!isInteger(issuedAt) || (issuedAt as number) >= (freshUntil as number)) throw invalid();
  const expiresAt = Math.min(releaseExpiresAt as number, freshUntil as number);
  if (Date.now() >= expiresAt * 1_000) throw new TvcError("ProverPolicyExpired");
  return {
    file: { release: releasePart, freshness: freshnessPart },
    version: version as number,
    maxAgeSecs: maxAgeSecs as number,
    issuedAt: issuedAt as number,
    expiresAt,
    fetchedAtMs: Date.now(),
  };
}

function readPart(part: unknown, invalid: () => TvcError): SignedProverPolicyPart {
  if (!isRecord(part)) throw invalid();
  const { payload, signatures, ...rest } = part;
  if (Object.keys(rest).length > 0 || typeof payload !== "string" || !LOWER_HEX.test(payload)) throw invalid();
  if (
    !Array.isArray(signatures) ||
    !signatures.every(
      (entry: unknown) =>
        isRecord(entry) &&
        Object.keys(entry).length === 2 &&
        typeof entry["public_key"] === "string" &&
        typeof entry["signature"] === "string",
    )
  ) {
    throw invalid();
  }
  return { payload, signatures: signatures as SignedProverPolicyPart["signatures"] };
}

function readPayload(payload: string, invalid: () => TvcError): Record<string, unknown> {
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeLowerHex(payload)));
  } catch {
    throw invalid();
  }
  if (!isRecord(decoded)) throw invalid();
  return decoded;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}
