import { isAddress } from "@solana/kit";

import { TvcError } from "../protocol/error.js";
import { decodeLowerHex } from "../protocol/hex.js";
import type { ShieldedIdentity, StoredWallet } from "./client.js";

const IDENTITY_KEYS = [
  "solanaAddress",
  "shieldedOwnerHash",
  "shieldedNullifierPublicKey",
  "shieldedViewingPublicKey",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: object, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function isLowerHex(value: unknown, bytes?: number): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    const decoded = decodeLowerHex(value);
    return bytes === undefined || decoded.length === bytes;
  } catch {
    return false;
  }
}

function isIdentity(value: unknown): value is ShieldedIdentity {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, IDENTITY_KEYS) &&
    typeof value.solanaAddress === "string" &&
    isAddress(value.solanaAddress) &&
    isLowerHex(value.shieldedOwnerHash, 32) &&
    isLowerHex(value.shieldedNullifierPublicKey, 32) &&
    isLowerHex(value.shieldedViewingPublicKey, 33)
  );
}

/**
 * `keys.stored` read back from the application's private storage for the
 * user, such as `JSON.parse` of an IndexedDB record: the identity and, unless
 * it was lost, the sealed seed. Anything else is `StorageCorrupted`. The value
 * is sensitive; see `StoredWallet`.
 */
export function parseStoredWallet(value: unknown): StoredWallet {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["identity", "sealedSeed"]) ||
    !isIdentity(value.identity) ||
    (value.sealedSeed !== undefined &&
      !(isRecord(value.sealedSeed) &&
        hasOnlyKeys(value.sealedSeed, ["sealedSeed"]) &&
        isLowerHex(value.sealedSeed.sealedSeed)))
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return value as StoredWallet;
}
