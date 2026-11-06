/**
 * The HTTP port this client depends on.
 *
 * It lives with its consumer rather than in `platform/`, which holds adapters
 * that sit *above* the client (browser storage, the wallet facades). Keeping
 * the port here is what stops the dependency edge from pointing both ways.
 *
 * The default is plain `fetch` with no platform-specific behaviour; supply your
 * own to add retries, tracing, or a pinned agent.
 */
export type SprEmbeddedWalletTransport = {
  fetch(input: URL, init?: RequestInit): Promise<Response>;
};

export function createDefaultTransport(): SprEmbeddedWalletTransport {
  return {
    fetch: (input, init) => fetch(input, init),
  };
}
