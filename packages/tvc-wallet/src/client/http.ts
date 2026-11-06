import { awaitWithSignal } from "./request.js";
import type { TvcTransport } from "./transport.js";
import { TvcError, TvcHttpError } from "../protocol/error.js";

const td = new TextDecoder("utf-8", { fatal: true });

/** `endpoint` with `path` appended to its path, keeping its query, such as an API key. */
export function gatewayUrl(endpoint: URL, path: string): URL {
  const url = new URL(endpoint);
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/${path}`;
  return url;
}

export function endpointUrl(endpoint: URL, path: string): URL {
  const base = new URL(endpoint);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL(path.replace(/^\/+/, ""), base);
}

/**
 * Reads an untrusted response body without first buffering an attacker-chosen
 * amount of data. TVC responses are canonical JSON, so malformed UTF-8 is a
 * protocol error rather than text that may be repaired with U+FFFD.
 */
export async function readBoundedText(response: Response, maxBytes: bigint, signal?: AbortSignal): Promise<string> {
  const body = await readBoundedBytes(response, maxBytes, signal);
  try {
    return td.decode(body);
  } catch {
    throw new TvcError("InvalidCanonicalJson");
  }
}

/** Reads an untrusted response body as bytes, refusing more than `maxBytes`. */
export async function readBoundedBytes(
  response: Response,
  maxBytes: bigint,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  signal?.throwIfAborted();
  if (maxBytes <= 0n || maxBytes > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new TvcError("ResponseTooLarge");
  }
  const limit = Number(maxBytes);
  if (!response.body) {
    const body = new Uint8Array(await awaitWithSignal(response.arrayBuffer(), signal));
    if (body.length > limit) throw new TvcError("ResponseTooLarge");
    return body;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await awaitWithSignal(reader.read(), signal);
      if (done) break;
      total += value.length;
      if (total > limit) throw new TvcError("ResponseTooLarge");
      chunks.push(value);
    }
  } finally {
    // A custom stream may never settle its cancellation promise.
    void reader.cancel().catch(() => undefined);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/**
 * Requires the object's own keys to be exactly `expected`. Rejecting only
 * unknown keys would let a peer omit a field and surface it downstream as an
 * `undefined` read rather than a protocol error.
 */
export function assertExactObjectKeys(
  value: unknown,
  expected: readonly string[],
  invalidObjectCode: string,
): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TvcError(invalidObjectCode);
  }
  const keys = Object.keys(value);
  for (const key of keys) {
    if (!expected.includes(key)) throw new TvcError("UnknownJsonField");
  }
  // serde surfaces a missing required field as a plain deserialization
  // failure, which the Rust protocol maps to InvalidCanonicalJson.
  if (keys.length !== expected.length) throw new TvcError("InvalidCanonicalJson");
}

/** Cancel a late custom-transport response as well as native fetch. */
export async function fetchWithSignal(
  transport: TvcTransport, url: URL, init?: RequestInit, signal?: AbortSignal,
): Promise<Response> {
  signal?.throwIfAborted();
  const work = transport.fetch(url, { ...init, ...(signal ? { signal } : {}) });
  try { return await awaitWithSignal(work, signal); }
  catch (error) {
    if (signal?.aborted) void work.then((response) => response.body?.cancel()).catch(() => undefined);
    throw error;
  }
}

export function httpError(response: Response, code: string): TvcHttpError {
  void response.body?.cancel().catch(() => undefined);
  return new TvcHttpError(code, response.status, response.headers.get("retry-after"));
}
