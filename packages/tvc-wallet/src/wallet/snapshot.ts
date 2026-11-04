import { requestScope } from "../client/request.js";
import {
  keyedWalletSnapshotCipher,
  walletSnapshotKey,
  type Bytes32,
  type RequestContext,
  type WalletStateCipher,
} from "@heliuslabs/spr";
import { sha256 } from "@noble/hashes/sha256";

import type { TvcKeys } from "./keys.js";

/**
 * The first-nullifier slot of the per-transaction key that keys the snapshot.
 * A nullifier is a BN254 field element, below 0x30..., so a value whose first
 * byte is 0xff is never one, and the key it selects belongs to no transaction.
 */
const SNAPSHOT_KEY_CONTEXT: Bytes32 = (() => {
  const context = sha256(new TextEncoder().encode("zolana-tvc/wallet-snapshot-key/v1"));
  context[0] = 0xff;
  return context as Bytes32;
})();

/**
 * The SDK's sealed snapshot cipher for a wallet the enclave holds. The
 * enclave mints one per-transaction viewing key under a context no
 * transaction can have; that key is the snapshot key's material, so the
 * snapshot opens for anyone who can drive this wallet's enclave operations and
 * for nobody else. The material is wiped once the AES key is imported.
 */
export async function snapshotCipher(keys: TvcKeys, context?: RequestContext): Promise<WalletStateCipher> {
  const scope = requestScope(context);
  try {
    scope.signal.throwIfAborted();
    const [viewingPublicKey] = keys.viewingPublicKeys();
    if (viewingPublicKey === undefined) throw new Error("MissingViewingKey");
    const transactionKeys = await keys.transactionKeys([
      { viewingPublicKey, firstNullifier: SNAPSHOT_KEY_CONTEXT },
    ], { ...context, signal: scope.signal });
    try {
      scope.signal.throwIfAborted();
      if (transactionKeys.length !== 1 || !transactionKeys[0]) throw new Error("BatchMismatch");
      const material = transactionKeys[0].secretBytes();
      try {
        const key = await walletSnapshotKey(material);
        scope.signal.throwIfAborted();
        return keyedWalletSnapshotCipher(keys.address(), key);
      } finally { material.fill(0); }
    } finally {
      for (const key of transactionKeys) key.destroy();
    }
  } finally { scope.dispose(); }
}
