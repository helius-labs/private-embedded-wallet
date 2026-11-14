import { awaitWithSignal } from "./request.js";
import { SprEmbeddedWalletError, SprEmbeddedWalletHttpError } from "../protocol/error.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import type { WalletDescriptor, WalletGrant } from "../protocol/types.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { endpointUrl, fetchWithSignal, gatewayUrl, httpError, readBoundedText } from "./http.js";
import type { SprEmbeddedWalletTransport } from "./transport.js";

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
 * Boot Proof beside its answer. The private-wallet path adds a grant; the
 * decryption-service path forwards the encrypted request as it is.
 */
export type GatewayBackend = {
  readonly kind: "gateway";
  /**
   * `…/v1/private-wallet` or `…/v1/decryption`, keeping any query such as
   * gatekeeper's `api-key`.
   */
  readonly endpoint: URL;
  /**
   * When set, operations are the enclave's `EncryptedRequest` alone (no
   * descriptor, no grant). The decryption gateway uses this.
   */
  readonly decryptionService?: true;
};

/**
 * Where the client reaches the enclave. Through either, the client verifies
 * the same evidence: the release policy, discovery, the ping and the Boot
 * Proof of each replica that answers.
 */
export type SprEmbeddedWalletBackend = EnclaveBackend | GatewayBackend;

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

function postJson(transport: SprEmbeddedWalletTransport, url: URL, body: string, signal?: AbortSignal): Promise<Response> {
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

/** The enclave's answer to `pingBody`, a QOS ping encrypted to its quorum key. */
export async function fetchPing(
  endpoint: URL,
  pingBody: string,
  transport: SprEmbeddedWalletTransport,
  signal?: AbortSignal,
): Promise<string> {
  const ping = await postJson(transport, endpointUrl(endpoint, "/v1/ping"), pingBody, signal);
  return readAnswer(ping, "BootProofUnverified", MAX_PING_RESPONSE_BYTES, signal);
}

/** Discovery and the answer to `pingBody`, a QOS ping encrypted to the pinned quorum key. */
export async function fetchSession(
  backend: SprEmbeddedWalletBackend,
  pingBody: string,
  transport: SprEmbeddedWalletTransport,
  signal?: AbortSignal,
): Promise<SessionAnswer> {
  signal?.throwIfAborted();
  switch (backend.kind) {
    case "enclave": {
      const info = await fetchWithSignal(
        transport, endpointUrl(backend.endpoint, "/v1/info"), undefined, signal,
      );
      const infoText = await readAnswer(info, "DiscoveryUntrusted", MAX_DISCOVERY_RESPONSE_BYTES, signal);
      return { infoText, pingText: await fetchPing(backend.endpoint, pingBody, transport, signal) };
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
  backend: SprEmbeddedWalletBackend,
  appProof: TurnkeyAppProofWire,
  signal?: AbortSignal,
): Promise<TurnkeyBootProofWire> {
  if (backend.kind !== "enclave" || !backend.resolveBootProof) {
    return Promise.reject(new SprEmbeddedWalletError("BootProofUnverified"));
  }
  return awaitWithSignal(backend.resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
    ...(signal ? { signal } : {}),
  }), signal);
}

/** What the request carries beside the ciphertext: the grant, unless a gateway adds it. */
export async function requestGrant(
  backend: SprEmbeddedWalletBackend,
  signal?: AbortSignal,
): Promise<{ readonly wallet_grant?: WalletGrant }> {
  if (backend.kind === "gateway") return {};
  if (!backend.walletGrant) throw new SprEmbeddedWalletError("WalletGrantRequired");
  return { wallet_grant: await awaitWithSignal(backend.walletGrant(signal), signal) };
}

/** Bytes the backend adds to a request before the enclave receives it. */
export function forwardedRequestBytes(backend: SprEmbeddedWalletBackend): number {
  if (backend.kind !== "gateway" || backend.decryptionService) return 0;
  return GATEWAY_GRANT_BYTES;
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
    throw new SprEmbeddedWalletHttpError("DescriptorExpired", response.status, response.headers.get("retry-after"));
  }
  const unavailable = response.status >= 500 || response.status === 424;
  return readAnswer(response, unavailable ? "OperationUnavailable" : "OperationRejected", maxBytes, signal);
}

/** Posts one encrypted request to the enclave's own ingress. */
export async function sendToEnclave(
  endpoint: URL,
  request: EncryptedRequestWire,
  transport: SprEmbeddedWalletTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<OperationAnswer> {
  const url = endpointUrl(endpoint, "/v1/operations");
  const response = await postJson(transport, url, canonicalizeJsonValue(request), signal);
  return { responseText: await readOperationAnswer(response, maxAnswerBytes, signal) };
}

/** Posts one encrypted request through a decryption-service gateway (no descriptor). */
export async function sendToDecryptionGateway(
  endpoint: URL,
  request: EncryptedRequestWire,
  transport: SprEmbeddedWalletTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<OperationAnswer> {
  const url = gatewayUrl(endpoint, "operations");
  const response = await postJson(transport, url, canonicalizeJsonValue(request), signal);
  const answer = parseStrictJson<{ response: unknown; bootProof: TurnkeyBootProofWire }>(
    await readOperationAnswer(response, maxAnswerBytes + MAX_BOOT_PROOF_BYTES, signal),
    GATEWAY_OPERATION_KEYS,
  );
  return { responseText: JSON.stringify(answer.response), bootProof: answer.bootProof };
}

/** Sends one encrypted request, whose enclave answer may take up to `maxAnswerBytes`. */
export async function sendOperation(
  backend: SprEmbeddedWalletBackend,
  request: EncryptedRequestWire,
  descriptor: WalletDescriptor,
  transport: SprEmbeddedWalletTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<OperationAnswer> {
  switch (backend.kind) {
    case "enclave":
      return sendToEnclave(backend.endpoint, request, transport, maxAnswerBytes, signal);
    case "gateway": {
      if (backend.decryptionService) {
        return sendToDecryptionGateway(backend.endpoint, request, transport, maxAnswerBytes, signal);
      }
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

/**
 * Sends one decryption-service encrypted request: direct to the enclave, or
 * through a gateway that attaches the Boot Proof (and takes no grant).
 */
export async function sendDecryptionOperation(
  backend: SprEmbeddedWalletBackend,
  request: EncryptedRequestWire,
  transport: SprEmbeddedWalletTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<OperationAnswer> {
  switch (backend.kind) {
    case "enclave":
      return sendToEnclave(backend.endpoint, request, transport, maxAnswerBytes, signal);
    case "gateway":
      return sendToDecryptionGateway(backend.endpoint, request, transport, maxAnswerBytes, signal);
  }
}
