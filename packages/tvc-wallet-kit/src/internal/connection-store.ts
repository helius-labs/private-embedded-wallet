import type {
  HeliusPrivateWalletSession,
  HeliusPrivateWalletStatus,
} from "helius-wallet-kit/core";

export type PrivateWalletView = Readonly<{
  status: HeliusPrivateWalletStatus;
  session: HeliusPrivateWalletSession | null;
  error: Error | null;
}>;

/** Opens a session; `signal` aborts when the wallet session it belongs to ends. */
export type OpenPrivateWallet = (signal: AbortSignal) => Promise<HeliusPrivateWalletSession>;

type Scope = {
  controller: AbortController;
  promise: Promise<HeliusPrivateWalletSession> | null;
  session: HeliusPrivateWalletSession | null;
};

const IDLE: PrivateWalletView = Object.freeze({ status: "idle", session: null, error: null });

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

/**
 * One private wallet connection per signed-in wallet, shared by every
 * consumer. A React provider subscribes to it; nothing here is React.
 */
export class PrivateWalletConnection {
  private view: PrivateWalletView = IDLE;
  private binding = "";
  private scope: Scope | null = null;
  private readonly listeners = new Set<() => void>();

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  readonly snapshot = (): PrivateWalletView => this.view;

  /** Ties the connection to one signed-in wallet; a change ends the session. */
  rebind(binding: string): void {
    if (binding === this.binding) return;
    this.binding = binding;
    this.abort();
    this.set(IDLE);
  }

  readonly disconnect = (): void => {
    this.abort();
    this.set(IDLE);
  };

  /** The connected session, the connect in progress, or a new one. */
  connect(
    open: OpenPrivateWallet,
    options?: { signal?: AbortSignal },
  ): Promise<HeliusPrivateWalletSession> {
    if (options?.signal?.aborted) {
      return Promise.reject(options.signal.reason ?? new DOMException("Aborted", "AbortError"));
    }
    const existing = this.scope;
    if (existing?.session) return Promise.resolve(existing.session);
    if (existing?.promise) return existing.promise;

    const controller = new AbortController();
    const signal = options?.signal
      ? AbortSignal.any([controller.signal, options.signal])
      : controller.signal;
    const scope: Scope = { controller, promise: null, session: null };
    this.scope = scope;
    this.set({ status: "connecting", session: null, error: null });

    let opened: Promise<HeliusPrivateWalletSession>;
    try {
      opened = Promise.resolve(open(signal));
    } catch (error) {
      opened = Promise.reject(error);
    }
    const promise = opened
      .then((session) => {
        signal.throwIfAborted();
        if (this.scope !== scope) throw new Error("PrivateWalletSessionExpired");
        scope.session = session;
        this.set({ status: "connected", session, error: null });
        return session;
      })
      .catch((error: unknown) => {
        const cancelled = signal.aborted;
        controller.abort(new Error("PrivateWalletSessionExpired"));
        if (this.scope === scope) {
          this.scope = null;
          this.set(cancelled ? IDLE : { status: "error", session: null, error: asError(error) });
        }
        throw error;
      });
    scope.promise = promise;
    return promise;
  }

  private abort(): void {
    const scope = this.scope;
    this.scope = null;
    scope?.controller.abort(new Error("PrivateWalletSessionExpired"));
  }

  private set(view: PrivateWalletView): void {
    this.view = view;
    for (const listener of this.listeners) listener();
  }
}
