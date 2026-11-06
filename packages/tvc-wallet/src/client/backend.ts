import { awaitWithSignal } from "./request.js";
import { TvcError, TvcHttpError } from "../protocol/error.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import type { WalletDescriptor, WalletGrant } from "../protocol/types.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { endpointUrl, fetchWithSignal, gatewayUrl, httpError, readBoundedText } from "./http.js";
import type { TvcTransport } from "./transport.js";

export type ResolveBootProofInput = {
  readonly appProof: TurnkeyAppProofWire;
  readonly bootProofLookupKey: string;
  readonly signal?: AbortSignal;
};

export type BootProofResolver = (input: ResolveBootProofInput) => Promise<TurnkeyBootProofWire>;

/** The enclave's public ingress. */
export type EnclaveBackend = {
  readonly kind: "enclave";
  readonly endpoint: URL;
  /** Fetches a replica's Boot Proof, such as with the caller's authenticated Turnkey session. */
  readonly resolveBootProof?: BootProofResolver;
  /**
   * A current grant for the descriptor and client key, sent beside every
   * request. The enclave refuses a request without one; the provider is asked
   * each time, so it can renew a grant near expiry.
   */
  readonly walletGrant?: (signal?: AbortSignal) => Promise<WalletGrant>;
};

/**
 * A tvc-gateway, such as Helius's behind gatekeeper. It returns each replica's
 * Boot Proof beside its answer and adds a grant to each operation.
 */
export type GatewayBackend = {
  readonly kind: "gateway";
  /** `…/v1/private-wallet`, keeping any query such as gatekeeper's `api-key`. */
  readonly endpoint: URL;
};

/**
 * Where the client reaches the enclave. Through either, the client verifies
 * the same evidence: the release policy, discovery, the ping and the Boot
 * Proof of each replica that answers.
 */
export type TvcBackend = EnclaveBackend | GatewayBackend;

/** The enclave's request fields around the ciphertext. */
export type EncryptedRequestWire = {
  readonly version: number;
  readonly quorum_key_id: string;
  readonly quorum_key_epoch: string;
  readonly ciphertext: string;
  readonly wallet_grant?: WalletGrant;
};

/** Discovery and the ping answer as text, and the Boot Proof when the backend returns it. */
export type SessionAnswer = {
  readonly infoText: string;
  readonly pingText: string;
  readonly bootProof?: TurnkeyBootProofWire;
};

/** The enclave's encrypted response as text, and the Boot Proof when the backend returns it. */
export type OperationAnswer = {
  readonly responseText: string;
  readonly bootProof?: TurnkeyBootProofWire;
};

const MAX_DISCOVERY_RESPONSE_BYTES = 64n * 1024n;
const MAX_PING_RESPONSE_BYTES = 64n * 1024n;
/** A Turnkey Boot Proof as a gateway returns it beside an enclave answer. */
const MAX_BOOT_PROOF_BYTES = 256n * 1024n;
const MAX_SESSION_RESPONSE_BYTES =
  MAX_DISCOVERY_RESPONSE_BYTES + MAX_PING_RESPONSE_BYTES + MAX_BOOT_PROOF_BYTES;
const SESSION_KEYS = ["info", "ping", "bootProof"] as const;
const GATEWAY_OPERATION_KEYS = ["response", "bootProof"] as const;
/** Room for the grant a gateway adds to the request it forwards. */
const GATEWAY_GRANT_BYTES = 1_024;

function postJson(transport: TvcTransport, url: URL, body: string, signal?: AbortSignal): Promise<Response> {
  return fetchWithSignal(transport, url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  }, signal);
}

async function readAnswer(
  response: Response,
  failureCode: string,
  maxBytes: bigint,
  signal?: AbortSignal,
): Promise<string> {
  if (!response.ok) throw httpError(response, failureCode);
  return readBoundedText(response, maxBytes, signal);
}

/** Discovery and the answer to `pingBody`, a QOS ping encrypted to the pinned quorum key. */
export async function fetchSession(
  backend: TvcBackend,
  pingBody: string,
  transport: TvcTransport,
  signal?: AbortSignal,
): Promise<SessionAnswer> {
  signal?.throwIfAborted();
  switch (backend.kind) {
    case "enclave": {
      const info = await fetchWithSignal(
        transport, endpointUrl(backend.endpoint, "/v1/info"), undefined, signal,
      );
      const infoText = await readAnswer(info, "DiscoveryUntrusted", MAX_DISCOVERY_RESPONSE_BYTES, signal);
      const ping = await postJson(transport, endpointUrl(backend.endpoint, "/v1/ping"), pingBody, signal);
      const pingText = await readAnswer(ping, "BootProofUnverified", MAX_PING_RESPONSE_BYTES, signal);
      return { infoText, pingText };
    }
    case "gateway": {
      const response = await postJson(transport, gatewayUrl(backend.endpoint, "session"), pingBody, signal);
      const session = parseStrictJson<{ info: unknown; ping: unknown; bootProof: TurnkeyBootProofWire }>(
        await readAnswer(response, "DiscoveryUntrusted", MAX_SESSION_RESPONSE_BYTES, signal),
        SESSION_KEYS,
      );
      return {
        infoText: JSON.stringify(session.info),
        pingText: JSON.stringify(session.ping),
        bootProof: session.bootProof,
      };
    }
  }
}

/** The Boot Proof of the replica that signed `appProof`, for an answer that carried none. */
export function lookupBootProof(
  backend: TvcBackend,
  appProof: TurnkeyAppProofWire,
  signal?: AbortSignal,
): Promise<TurnkeyBootProofWire> {
  if (backend.kind !== "enclave" || !backend.resolveBootProof) {
    return Promise.reject(new TvcError("BootProofUnverified"));
  }
  return awaitWithSignal(backend.resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
    ...(signal ? { signal } : {}),
  }), signal);
}

/** What the request carries beside the ciphertext: the grant, unless a gateway adds it. */
export async function requestGrant(
  backend: TvcBackend,
  signal?: AbortSignal,
): Promise<{ readonly wallet_grant?: WalletGrant }> {
  if (backend.kind === "gateway") return {};
  if (!backend.walletGrant) throw new TvcError("WalletGrantRequired");
  return { wallet_grant: await awaitWithSignal(backend.walletGrant(signal), signal) };
}

/** Bytes the backend adds to a request before the enclave receives it. */
export function forwardedRequestBytes(backend: TvcBackend): number {
  return backend.kind === "gateway" ? GATEWAY_GRANT_BYTES : 0;
}

/** Room for a refusal's JSON: the enclave's `{"error"}` or a gateway's problem document. */
const MAX_REFUSAL_BYTES = 4_096n;

/**
 * Whether a 403 names `DescriptorExpired`: the enclave answers
 * `{"error": "DescriptorExpired"}`, which a gateway forwards as it is, and a
 * gateway that refuses the descriptor itself answers a problem with that
 * `code`.
 */
async function refusesExpiredDescriptor(response: Response, signal?: AbortSignal): Promise<boolean> {
  if (response.status !== 403) return false;
  let refusal: unknown;
  try {
    refusal = JSON.parse(await readBoundedText(response, MAX_REFUSAL_BYTES, signal));
  } catch {
    signal?.throwIfAborted();
    return false;
  }
  if (!refusal || typeof refusal !== "object") return false;
  const { code, error } = refusal as { code?: unknown; error?: unknown };
  return code === "DescriptorExpired" || error === "DescriptorExpired";
}

/**
 * The application answers a rejected request with 4xx, and a release that
 * cannot serve one with 5xx; a gateway answers 424 when the enclave or Turnkey
 * did not. A refused expired descriptor is `DescriptorExpired`.
 */
async function readOperationAnswer(response: Response, maxBytes: bigint, signal?: AbortSignal): Promise<string> {
  if (await refusesExpiredDescriptor(response, signal)) {
    throw new TvcHttpError("DescriptorExpired", response.status, response.headers.get("retry-after"));
  }
  const unavailable = response.status >= 500 || response.status === 424;
  return readAnswer(response, unavailable ? "OperationUnavailable" : "OperationRejected", maxBytes, signal);
}

/** Sends one encrypted request, whose enclave answer may take up to `maxAnswerBytes`. */
export async function sendOperation(
  backend: TvcBackend,
  request: EncryptedRequestWire,
  descriptor: WalletDescriptor,
  transport: TvcTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<OperationAnswer> {
  switch (backend.kind) {
    case "enclave": {
      const url = endpointUrl(backend.endpoint, "/v1/operations");
      const response = await postJson(transport, url, canonicalizeJsonValue(request), signal);
      return { responseText: await readOperationAnswer(response, maxAnswerBytes, signal) };
    }
    case "gateway": {
      const url = gatewayUrl(backend.endpoint, "operations");
      const response = await postJson(transport, url, canonicalizeJsonValue({ descriptor, request }), signal);
      const answer = parseStrictJson<{ response: unknown; bootProof: TurnkeyBootProofWire }>(
        await readOperationAnswer(response, maxAnswerBytes + MAX_BOOT_PROOF_BYTES, signal),
        GATEWAY_OPERATION_KEYS,
      );
      return { responseText: JSON.stringify(answer.response), bootProof: answer.bootProof };
    }
  }
}
