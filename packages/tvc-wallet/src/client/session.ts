import { awaitWithSignal, requestScope, type TvcRequestOptions } from "./request.js";
import {
  connectAndVerifyTvc,
  type ConnectedTvcRuntime,
  type TvcConnectionConfig,
} from "./connection.js";
import type {
  OperationExecutionContext,
  OperationsConfig,
} from "./operation-executor.js";

export type TvcSessionConfig = TvcConnectionConfig & {
  /** The wallet the operations act on and the key that signs them. */
  operations: OperationsConfig;
};

/**
 * The client's one verified connection, made on first use. Verification runs
 * again once the release policy's validity window no longer holds, and after
 * `forget`; nothing else replaces it.
 */
export type TvcSession = {
  /** The operation context of the verified connection, verifying first when there is none or it no longer holds. */
  context(options?: TvcRequestOptions): Promise<OperationExecutionContext>;
  /** Drops `context` if it is still the current one, so the next call verifies again. */
  forget(context: OperationExecutionContext): void;
};

/** Whether the connection's release policy is still in force. Operations check the same window again before they sign. */
function holds(context: OperationExecutionContext): boolean {
  const now = context.nowMs();
  return now >= context.releasePolicyValidFromMs && now <= context.releasePolicyExpiresAtMs;
}

export function sessionFromConnector(
  connect: (signal: AbortSignal) => Promise<ConnectedTvcRuntime>,
  operations: OperationsConfig,
  requestTimeoutMs?: number,
): TvcSession {
  let active: OperationExecutionContext | null = null;
  type Flight = { controller: AbortController; promise: Promise<OperationExecutionContext>; users: number };
  let pending: Flight | null = null;

  return {
    async context(options): Promise<OperationExecutionContext> {
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
            const runtime = await connect(controller.signal);
            // An abandoned connector may ignore cancellation and finish after its replacement.
            controller.signal.throwIfAborted();
            const context = { ...runtime, operations };
            active = context;
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
  };
}

export function createTvcSession(config: TvcSessionConfig): TvcSession {
  // Single-flighted: concurrent first calls share one verification.
  return sessionFromConnector((signal) => connectAndVerifyTvc(config, signal), config.operations, config.requestTimeoutMs);
}
