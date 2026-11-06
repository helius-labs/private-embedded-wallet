import { awaitWithSignal, requestScope, type SprEmbeddedWalletRequestOptions } from "./request.js";
import {
  connectAndVerifyTvc,
  type ConnectedTvcRuntime,
  type SprEmbeddedWalletConnectionConfig,
} from "./connection.js";

/**
 * The client's one verified connection, made on first use. Verification runs
 * again once the release policy's validity window no longer holds, and after
 * `forget` or `reset`; nothing else replaces it.
 */
export type SprEmbeddedWalletSession = {
  /** The verified connection, verifying first when there is none or it no longer holds. */
  context(options?: SprEmbeddedWalletRequestOptions): Promise<ConnectedTvcRuntime>;
  /** Drops `context` if it is still the current one, so the next call verifies again. */
  forget(context: ConnectedTvcRuntime): void;
  /** Drops the current connection and any verification in flight, so the next call verifies anew. */
  reset(): void;
};

/** Whether the connection's release policy is still in force. Operations check the same window again before they sign. */
function holds(context: ConnectedTvcRuntime): boolean {
  const now = context.nowMs();
  return now >= context.releasePolicyValidFromMs && now <= context.releasePolicyExpiresAtMs;
}

export function sessionFromConnector(
  connect: (signal: AbortSignal) => Promise<ConnectedTvcRuntime>,
  requestTimeoutMs?: number,
): SprEmbeddedWalletSession {
  let active: ConnectedTvcRuntime | null = null;
  type Flight = { controller: AbortController; promise: Promise<ConnectedTvcRuntime>; users: number };
  let pending: Flight | null = null;

  return {
    async context(options): Promise<ConnectedTvcRuntime> {
      const scope = requestScope(options, requestTimeoutMs);
      let flight: Flight | undefined;
      try {
        scope.signal.throwIfAborted();
        if (active && holds(active)) return active;
        active = null;
        if (!pending) {
          const controller = new AbortController();
          const current: Flight = { controller, users: 0, promise: Promise.resolve().then(async () => {
            controller.signal.throwIfAborted();
            const context = await connect(controller.signal);
            // An abandoned connector may ignore cancellation and finish after its
            // replacement, and a reset one must not become current.
            controller.signal.throwIfAborted();
            if (pending === current) active = context;
            return context;
          }).finally(() => { if (pending === current) pending = null; }) };
          pending = current;
        }
        flight = pending;
        flight.users += 1;
        return await awaitWithSignal(flight.promise, scope.signal);
      } finally {
        scope.dispose();
        if (flight && --flight.users === 0 && pending === flight) {
          pending = null;
          // One cancelled caller must not cancel another caller's verification.
          flight.controller.abort(scope.signal.reason);
        }
      }
    },

    forget(context): void {
      if (active === context) active = null;
    },

    reset(): void {
      active = null;
      pending = null;
    },
  };
}

export function createSprEmbeddedWalletSession(config: SprEmbeddedWalletConnectionConfig): SprEmbeddedWalletSession {
  // Single-flighted: concurrent first calls share one verification.
  return sessionFromConnector((signal) => connectAndVerifyTvc(config, signal), config.requestTimeoutMs);
}
