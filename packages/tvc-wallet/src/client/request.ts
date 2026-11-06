import { SprEmbeddedWalletError } from "../protocol/error.js";

/** Applies to one verification or enclave operation, including its proof lookup. */
export interface SprEmbeddedWalletRequestOptions {
  readonly signal?: AbortSignal;
  /** Total time allowed in milliseconds. Defaults to the client setting, or two minutes. */
  readonly timeoutMs?: number;
}

export function requestScope(options: SprEmbeddedWalletRequestOptions = {}, defaultTimeoutMs = 120_000) {
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
    throw new SprEmbeddedWalletError("InvalidRequestTimeout");
  }
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(new DOMException("TVC request timed out", "TimeoutError")), timeoutMs);
  return { signal, dispose: () => clearTimeout(timer) };
}

/** Only race work whose late result cannot authorize, publish a connection, or write storage. */
export async function awaitWithSignal<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return work;
  let abort!: () => void;
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
  try {
    const result = await Promise.race([work, cancelled]);
    signal.throwIfAborted();
    return result;
  } finally { signal.removeEventListener("abort", abort); }
}
