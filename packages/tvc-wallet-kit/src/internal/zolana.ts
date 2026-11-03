import { createZolanaClient } from "@heliuslabs/zolana";
import { SignedTeePolicy, type ZolanaClient } from "@heliuslabs/zolana/client";

const INDEXER_PATH = "/api/tvc/zolana/indexer/";
const INDEXER_ATTEMPTS = 3;
const RPC_ATTEMPTS = 3;
const INDEXER_REQUEST_TIMEOUT_MS = 10_000;
const OTHER_REQUEST_TIMEOUT_MS = 60_000;
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function requestUrl(input: URL | RequestInfo, origin: string): URL {
  const raw = input instanceof Request ? input.url : String(input);
  return new URL(raw, origin);
}

function privateWalletFetch(origin: string, rpcPathname: string): typeof fetch {
  return async (input, init) => {
    const url = requestUrl(input, origin);
    const attempts = url.pathname.startsWith(INDEXER_PATH)
      ? INDEXER_ATTEMPTS
      : url.pathname === rpcPathname
        ? RPC_ATTEMPTS
        : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const timeout = AbortSignal.timeout(
          url.pathname.startsWith(INDEXER_PATH)
            ? INDEXER_REQUEST_TIMEOUT_MS
            : OTHER_REQUEST_TIMEOUT_MS,
        );
        const signal = init?.signal
          ? AbortSignal.any([init.signal, timeout])
          : timeout;
        const response = await fetch(input, { ...init, signal });
        if (
          RETRYABLE_STATUS.has(response.status) &&
          attempt + 1 < attempts
        ) {
          await response.arrayBuffer();
          await delay(250 * 2 ** attempt);
          continue;
        }
        return response;
      } catch (error) {
        lastError = error;
        if (init?.signal?.aborted || attempt + 1 === attempts) break;
        await delay(250 * 2 ** attempt);
      }
    }
    throw new Error("PrivateWalletServiceUnavailable", { cause: lastError });
  };
}

export function createPrivateZolanaClient(
  origin: string,
  solanaRpcUrl: string,
): Promise<ZolanaClient> {
  const rpcPathname = new URL(solanaRpcUrl, origin).pathname;
  return createZolanaClient({
    solanaRpcUrl,
    indexerUrl: `${origin}/api/tvc/zolana/indexer`,
    proverUrl: `${origin}/api/tvc/zolana/prover`,
    allowInsecureHttp: new URL(origin).protocol === "http:",
    proverTee: SignedTeePolicy.forNetwork("devnet"),
    fetch: privateWalletFetch(origin, rpcPathname),
    // The enclave completes resolved proof inputs; it has no indexed proving.
    proofDataSource: "client",
  });
}
