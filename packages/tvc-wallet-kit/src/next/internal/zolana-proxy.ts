import { PRIVATE_WALLET_DEPLOYMENT } from "../../internal/deployment";

const MAX_BODY_BYTES = 4 * 1024 * 1024;
const INDEXER_TIMEOUT_MS = 10_000;
const PROVER_TIMEOUT_MS = 60_000;
/** A TEE prover proves synchronously, so the answer is the proof. */
const SEALED_PROOF_TIMEOUT_MS = 90_000;
const TEE_HEADER = "spr-tee";
const TEE_ENC_HEADER = "spr-tee-enc";
const TEE_VERSION = "v1";
const ATTESTATION_ROUTE = "attestation";
const HEX_32 = /^[0-9a-f]{64}$/u;
const INDEXER_METHODS = new Set([
  "getEncryptedUtxosByTags",
  "getShieldedTransactionsByTags",
  "getShieldedTransactionsByNullifiers",
  "getShieldedTransactionsBySignature",
  "getMerkleProofs",
  "getNonInclusionProofs",
]);

type Service = "indexer" | "prover";
/** A proof, `prove/<key>`; `<key>` is a proving key file name. */
const PROVE_ROUTE = /^prove\/[a-z0-9_]{1,64}$/u;
/** A proof's status poll, `prove/<key>/status`. */
const PROVE_STATUS_ROUTE = /^prove\/[a-z0-9_]{1,64}\/status$/u;
const HELIUS_RPC_HOST = /(^|\.)helius-rpc\.com$/u;

function errorResponse(status = 502): Response {
  return Response.json(
    { error: "ZolanaProxyFailed" },
    { status, headers: { "cache-control": "no-store" } },
  );
}

function configuredUpstream(service: Service): URL {
  const upstream = new URL(
    service === "indexer"
      ? process.env.ZOLANA_INDEXER_URL?.trim() ||
          PRIVATE_WALLET_DEPLOYMENT.indexerUrl
      : process.env.ZOLANA_PROVER_URL?.trim() ||
          PRIVATE_WALLET_DEPLOYMENT.proverUrl,
  );
  if (upstream.protocol !== "http:" && upstream.protocol !== "https:") {
    throw new Error("InvalidZolanaUpstream");
  }
  return upstream;
}

/** `path` under the service's upstream, with the server's API key for gatekeeper. */
function upstreamUrl(service: Service, path: string): URL {
  const upstream = configuredUpstream(service);
  upstream.pathname = `${upstream.pathname.replace(/\/+$/u, "")}/${path}`;
  upstream.search = "";
  if (HELIUS_RPC_HOST.test(upstream.hostname)) {
    const apiKey = process.env.HELIUS_API_KEY?.trim();
    if (!apiKey) throw new Error("HeliusApiKeyRequired");
    upstream.searchParams.set("api-key", apiKey);
  }
  return upstream;
}

/** `route` under the service's upstream, with a status poll's job id. */
function targetUrl(service: Service, route: string, request: Request): URL {
  const upstream = upstreamUrl(service, route);
  if (service === "prover" && PROVE_STATUS_ROUTE.test(route)) {
    const jobId = new URL(request.url).searchParams.get("jobId");
    if (jobId === null || !/^[A-Za-z0-9_-]{1,256}$/u.test(jobId)) {
      throw new Error("InvalidProverJob");
    }
    upstream.searchParams.set("jobId", jobId);
  }
  return upstream;
}

async function bufferedResponse(response: Response): Promise<Response> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > MAX_BODY_BYTES) {
    return errorResponse();
  }
  const body = await response.arrayBuffer();
  if (body.byteLength > MAX_BODY_BYTES) return errorResponse();
  const headers = new Headers({
    "content-type": response.headers.get("content-type") ?? "application/json",
    "cache-control": "no-store",
  });
  const tee = response.headers.get(TEE_HEADER);
  if (tee !== null) headers.set(TEE_HEADER, tee);
  return new Response(body, { status: response.status, headers });
}

async function boundedBody(request: Request): Promise<ArrayBuffer | null> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > MAX_BODY_BYTES) return null;
  const body = await request.arrayBuffer();
  return body.byteLength > MAX_BODY_BYTES ? null : body;
}

/**
 * A proof the enclave sealed for its route, `prove/<key>`: forwarded with its
 * headers and body unchanged, since only the attested prover can open it.
 */
async function proxySealedProof(route: string, request: Request): Promise<Response> {
  const enc = request.headers.get(TEE_ENC_HEADER);
  if (
    !PROVE_ROUTE.test(route) ||
    request.headers.get(TEE_HEADER) !== TEE_VERSION ||
    enc === null ||
    !HEX_32.test(enc)
  ) {
    return errorResponse(400);
  }
  const body = await boundedBody(request);
  if (body === null) return errorResponse(413);
  const upstream = upstreamUrl("prover", route);
  const response = await fetch(upstream, {
    method: "POST",
    headers: {
      accept: "application/octet-stream",
      "content-type": "application/octet-stream",
      [TEE_HEADER]: TEE_VERSION,
      [TEE_ENC_HEADER]: enc,
    },
    body,
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(SEALED_PROOF_TIMEOUT_MS),
  });
  return bufferedResponse(response);
}

/** The prover's attestation for the client's nonce, for the enclave to verify. */
async function proxyAttestation(request: Request): Promise<Response> {
  const nonce = new URL(request.url).searchParams.get("nonce");
  if (nonce === null || !HEX_32.test(nonce)) return errorResponse(400);
  const upstream = upstreamUrl("prover", ATTESTATION_ROUTE);
  upstream.searchParams.set("nonce", nonce);
  const response = await fetch(upstream, {
    headers: { accept: "application/json" },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(PROVER_TIMEOUT_MS),
  });
  return bufferedResponse(response);
}

export async function proxyZolanaPost(
  service: string,
  route: string,
  request: Request,
): Promise<Response> {
  const selected =
    service === "indexer" || service === "prover" ? service : null;
  if (selected === "prover" && request.headers.has(TEE_HEADER)) {
    return await withApiKeyRequired(() => proxySealedProof(route, request));
  }
  const allowed =
    selected !== null &&
    ((selected === "indexer" && INDEXER_METHODS.has(route)) ||
      (selected === "prover" && PROVE_ROUTE.test(route)));
  if (!allowed || selected === null) return errorResponse(404);
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > MAX_BODY_BYTES) {
    return errorResponse(413);
  }
  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_BODY_BYTES) return errorResponse(413);
  let target: URL;
  try {
    target = targetUrl(selected, route, request);
  } catch (error) {
    if (error instanceof Error && error.message === "HeliusApiKeyRequired") return errorResponse(503);
    throw error;
  }
  const response = await fetch(target, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body,
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(
      selected === "indexer" ? INDEXER_TIMEOUT_MS : PROVER_TIMEOUT_MS,
    ),
  });
  return bufferedResponse(response);
}

export async function proxyZolanaGet(
  service: string,
  route: string,
  request: Request,
): Promise<Response> {
  if (service === "prover" && route === ATTESTATION_ROUTE) {
    return await withApiKeyRequired(() => proxyAttestation(request));
  }
  if (service !== "prover" || !PROVE_STATUS_ROUTE.test(route)) {
    return errorResponse(404);
  }
  let target: URL;
  try {
    target = targetUrl("prover", route, request);
  } catch (error) {
    if (error instanceof Error && error.message === "HeliusApiKeyRequired") return errorResponse(503);
    throw error;
  }
  const response = await fetch(target, {
    headers: { accept: "application/json" },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(PROVER_TIMEOUT_MS),
  });
  return bufferedResponse(response);
}

async function withApiKeyRequired(proxy: () => Promise<Response>): Promise<Response> {
  try {
    return await proxy();
  } catch (error) {
    if (error instanceof Error && error.message === "HeliusApiKeyRequired") return errorResponse(503);
    throw error;
  }
}
