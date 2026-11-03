import type { WalletKeys } from "@heliuslabs/zolana";

export class PrivateWalletSessionExpiredError extends Error {
  constructor() {
    super("PrivateWalletSessionExpired");
    this.name = "PrivateWalletSessionExpiredError";
  }
}

function activeSignal(signal: AbortSignal): AbortSignal {
  if (signal.aborted) throw new PrivateWalletSessionExpiredError();
  return signal;
}

function operationContext<T extends { signal?: AbortSignal } | undefined>(
  context: T,
  sessionSignal: AbortSignal,
): T {
  const signal = context?.signal
    ? AbortSignal.any([context.signal, activeSignal(sessionSignal)])
    : activeSignal(sessionSignal);
  return { ...context, signal } as T;
}

/** Prevents a retained key object from authorizing work after its wallet session changes. */
export function revocableWalletKeys(
  keys: WalletKeys,
  sessionSignal: AbortSignal,
): WalletKeys {
  const assertActive = () => activeSignal(sessionSignal);
  return {
    address() {
      assertActive();
      return keys.address();
    },
    viewingPublicKeys() {
      assertActive();
      return keys.viewingPublicKeys();
    },
    async decrypt(requests, context) {
      const result = await keys.decrypt(
        requests,
        operationContext(context, sessionSignal),
      );
      assertActive();
      return result;
    },
    async derive(requests, context) {
      const result = await keys.derive(
        requests,
        operationContext(context, sessionSignal),
      );
      assertActive();
      return result;
    },
    async transactionKeys(requests, context) {
      const result = await keys.transactionKeys(
        requests,
        operationContext(context, sessionSignal),
      );
      assertActive();
      return result;
    },
    async prove(inputs, context) {
      const result = await keys.prove(
        inputs,
        operationContext(context, sessionSignal),
      );
      assertActive();
      return result;
    },
    async proveMerge(inputs, context) {
      const result = await keys.proveMerge(
        inputs,
        operationContext(context, sessionSignal),
      );
      assertActive();
      return result;
    },
  };
}
