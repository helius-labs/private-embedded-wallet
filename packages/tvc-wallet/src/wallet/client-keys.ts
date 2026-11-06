import type { OperationsConfig } from "../client/operation-executor.js";
import type { WalletDescriptor } from "../protocol/types.js";

/** The key the client signs requests with, and the descriptor that lists it. */
export type SprEmbeddedWalletClientKey = {
  /** Names the key. When the current key's id changes, the client verifies the enclave again. */
  readonly id: string;
  /**
   * The descriptor that lists the key and the signer that signs with it,
   * enrolling the key on first use and again when the descriptor expires.
   */
  operations(signal?: AbortSignal): Promise<OperationsConfig>;
  /**
   * Drops `descriptor`, which the backend refused as expired, so the next
   * `operations` enrolls the key again. A key that cannot enroll has none.
   */
  readonly expire?: (descriptor: WalletDescriptor) => void;
};

/** Where the client's request key comes from: the Turnkey session, or a fixed descriptor and signer. */
export type SprEmbeddedWalletClientKeys = {
  /** The wallet's Solana address, when it is known before any request. */
  readonly solanaAddress?: string;
  /** The key to sign the next request with. */
  current(signal?: AbortSignal): Promise<SprEmbeddedWalletClientKey>;
};

/** One descriptor and the signer of the key it lists, for tests and the local testkit. */
export function fixedClientKeys(operations: OperationsConfig): SprEmbeddedWalletClientKeys {
  const key: SprEmbeddedWalletClientKey = {
    id: operations.signer.clientKeyId,
    operations: () => Promise.resolve(operations),
  };
  return {
    solanaAddress: operations.descriptor.address,
    current: () => Promise.resolve(key),
  };
}
