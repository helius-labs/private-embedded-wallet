import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/hashes/utils";

import { fetchWithSignal, gatewayUrl, httpError, readBoundedBytes, readBoundedText } from "../client/http.js";
import { createDefaultTransport, type TvcTransport } from "../client/transport.js";
import { TvcError, TvcHttpError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ProverRequest, ProverSealing, SealedProverRequest } from "../protocol/types.js";
import type { HeldProverPolicy, TvcProverPolicy } from "./prover-policy.js";

/** The encrypted prover wire contract, v1 (zolana `prover/tee/WIRE_CONTRACT.md`). */
const HEADER_VERSION = "Spr-Tee";
const HEADER_ENC = "Spr-Tee-Enc";
const VERSION = "v1";
const ATTESTATION_PATH = "attestation";
/** The prover no longer holds the key the request was sealed to. */
const KEY_LOST = "tee_decryption_failed";
const MAX_ATTESTATION_BYTES = 1n << 20n;
const MAX_ANSWER_BYTES = 1n << 20n;
const MAX_ERROR_BYTES = 4096n;
const RESPONSE_NONCE_BYTES = 12;
/** Mirrors `MAX_PROVE_INPUTS` in `crates/protocol/src/constants.rs`. */
export const MAX_PROVE_INPUTS = 52;
/** The SDK's circuit types and their proving-key families. */
const FAMILIES = {
  "transfer-confidential": "transfer_confidential",
  "transfer-ring": "transfer_ring",
  merge: "merge",
  "merge-ring": "merge_ring",
} as const;

/** Whether `value` is a circuit type the enclave proves. */
export function isProveCircuit(value: unknown): value is keyof typeof FAMILIES {
  return typeof value === "string" && Object.hasOwn(FAMILIES, value);
}

/**
 * Where the client proves and under which policy. `url` is the prover's base
 * URL, such as a regional prover or `https://<gateway>/v1/spr?api-key=<key>`:
 * the attestation and proof routes are appended to its path and its query is
 * kept. `policy` is the signed policy file of the network the enclave image
 * was built for, usually `TvcProverPolicy.forNetwork(network)`.
 */
export type TvcProverConfig = {
  readonly url: string;
  readonly policy: TvcProverPolicy;
  readonly transport?: TvcTransport;
};

/** A prover's answer to a sealed request that could not be opened as a proof. */
export type ProverAnswer =
  | { readonly kind: "proof"; readonly body: unknown }
  | { readonly kind: "keyLost" };

function slotCount(value: unknown): number {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_PROVE_INPUTS) {
    throw new TvcError("InvalidProverRequest");
  }
  return value.length;
}

/** The proving key file name, without `.key`; mirrors the enclave's `proving_key`. */
export function provingKeyName(request: ProverRequest): string {
  const circuit = request["circuitType"];
  if (!isProveCircuit(circuit)) throw new TvcError("InvalidProverRequest");
  const inputs = slotCount(request["inputs"]);
  const outputs = circuit.startsWith("merge") ? 1 : slotCount(request["outputs"]);
  return `${FAMILIES[circuit]}_${inputs}_${outputs}`;
}

/**
 * The route a request for `key` is sealed to: its path below the prover's URL,
 * whatever path a gateway or proxy serves that URL on. The enclave seals to
 * nothing else.
 */
export function proverTarget(key: string): string {
  return `/prove/${key}`;
}

/** A prover's attestation for one nonce, and when the client fetched it. */
export type ProverAttestation = {
  readonly nonce: string;
  readonly attestation: Readonly<Record<string, unknown>>;
  readonly fetchedAtMs: number;
};

/**
 * Asks the prover to attest for a fresh nonce. The enclave verifies the
 * attestation; the client only carries it.
 */
export async function fetchAttestation(
  config: TvcProverConfig,
  signal?: AbortSignal,
): Promise<ProverAttestation> {
  const nonce = encodeLowerHex(randomBytes(32));
  const url = gatewayUrl(new URL(config.url), ATTESTATION_PATH);
  url.searchParams.set("nonce", nonce);
  const transport = config.transport ?? createDefaultTransport();
  const response = await fetchWithSignal(transport, url, { method: "GET", redirect: "error" }, signal);
  if (!response.ok) throw httpError(response, "ProverAttestationUnavailable");
  let attestation: unknown;
  try {
    attestation = JSON.parse(await readBoundedText(response, MAX_ATTESTATION_BYTES, signal));
  } catch (error) {
    if (error instanceof TvcError && error.code === "ResponseTooLarge") throw error;
    throw new TvcError("ProverAttestationInvalid");
  }
  if (typeof attestation !== "object" || attestation === null || Array.isArray(attestation)) {
    throw new TvcError("ProverAttestationInvalid");
  }
  return { nonce, attestation: attestation as Record<string, unknown>, fetchedAtMs: Date.now() };
}

/** What the enclave needs to seal `request` to the attested prover. */
export function sealingFor(
  policy: HeldProverPolicy,
  attested: ProverAttestation,
  request: ProverRequest,
): ProverSealing {
  return {
    target: proverTarget(provingKeyName(request)),
    nonce: attested.nonce,
    attestation: attested.attestation,
    policy: policy.file,
  };
}

/**
 * Posts a sealed request to its proving key's route under `url` and opens the
 * answer. A prover that rebooted onto a new key answers `keyLost`, and the
 * caller attests again.
 */
export async function submitSealed(
  config: TvcProverConfig,
  sealed: SealedProverRequest,
  signal?: AbortSignal,
): Promise<ProverAnswer> {
  const url = gatewayUrl(new URL(config.url), sealed.target.replace(/^\/+/, ""));
  const transport = config.transport ?? createDefaultTransport();
  const response = await fetchWithSignal(
    transport,
    url,
    {
      method: "POST",
      headers: {
        [HEADER_VERSION]: VERSION,
        [HEADER_ENC]: sealed.enc,
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array(decodeLowerHex(sealed.ciphertext)),
      redirect: "error",
    },
    signal,
  );
  if (response.headers.get(HEADER_VERSION) !== VERSION) {
    if (response.ok) {
      void response.body?.cancel().catch(() => undefined);
      throw new TvcError("ProverAnswerUnencrypted");
    }
    if (response.status === 400 && (await errorCode(response, signal)) === KEY_LOST) {
      return { kind: "keyLost" };
    }
    throw httpError(response, "ProverRefused");
  }
  const { status, body } = decryptProverAnswer(
    decodeLowerHex(sealed.response_key),
    await readBoundedBytes(response, MAX_ANSWER_BYTES, signal),
  );
  if (status < 200 || status >= 300) {
    throw new TvcHttpError("ProverRefused", status, response.headers.get("retry-after"));
  }
  try {
    return { kind: "proof", body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) };
  } catch {
    throw new TvcError("ProverAnswerInvalid");
  }
}

/**
 * Opens an answer under the wire contract: a 12-byte nonce, then AES-256-GCM
 * over the status as a big-endian `u16` followed by the body.
 */
export function decryptProverAnswer(
  responseKey: Uint8Array,
  encrypted: Uint8Array,
): { status: number; body: Uint8Array } {
  let plaintext: Uint8Array;
  try {
    plaintext = gcm(responseKey, encrypted.subarray(0, RESPONSE_NONCE_BYTES)).decrypt(
      encrypted.subarray(RESPONSE_NONCE_BYTES),
    );
  } catch {
    throw new TvcError("ProverAnswerInvalid");
  }
  if (plaintext.length < 2) throw new TvcError("ProverAnswerInvalid");
  return {
    status: new DataView(plaintext.buffer, plaintext.byteOffset).getUint16(0, false),
    body: plaintext.subarray(2),
  };
}

async function errorCode(response: Response, signal?: AbortSignal): Promise<string | undefined> {
  try {
    const answer: unknown = JSON.parse(await readBoundedText(response.clone(), MAX_ERROR_BYTES, signal));
    return typeof answer === "object" && answer !== null && "code" in answer && typeof answer.code === "string"
      ? answer.code
      : undefined;
  } catch {
    return undefined;
  }
}
