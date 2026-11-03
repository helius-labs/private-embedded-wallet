import type { HeliusTvcAuthority } from "helius-wallet-kit/core";
import type { ShieldedIdentity } from "@zolana/tvc-wallet";
import {
  clearRecord,
  hasOnlyKeys,
  loadRecord,
  parsePersistentBrowserTvcWalletState,
  parseShieldedIdentity,
  saveRecord,
  type PersistentBrowserTvcWalletState,
} from "@zolana/tvc-wallet/browser";
import { TvcError } from "@zolana/tvc-wallet/protocol";

const DATABASE_NAME = "helius-wallet-kit-private-v2";
const STATE_RECORD_PREFIX = "wallet-binding:";
const IDENTITY_RECORD_PREFIX = "known-identity:";
const CORE_KEYS = [
  "version",
  "clientKeyId",
  "walletDescriptor",
  "identity",
  "sealedSeed",
  "registered",
] as const;
const STATE_KEYS = [
  ...CORE_KEYS,
  "turnkeyServicePublicKey",
  "tvcAuthority",
] as const;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const COMPRESSED_P256 = /^(02|03)[0-9a-f]{64}$/u;

export type PrivateWalletState = PersistentBrowserTvcWalletState & {
  readonly turnkeyServicePublicKey: string;
  readonly tvcAuthority: HeliusTvcAuthority;
};

function validAuthority(value: unknown): value is HeliusTvcAuthority {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const authority = value as Partial<HeliusTvcAuthority>;
  return (
    hasOnlyKeys(value, ["serviceUserId", "apiKeyId"]) &&
    UUID.test(authority.serviceUserId ?? "") &&
    UUID.test(authority.apiKeyId ?? "")
  );
}

export function parsePrivateWalletState(
  value: unknown,
): PrivateWalletState | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TvcError("StorageCorrupted");
  }
  const state = value as Partial<PrivateWalletState>;
  parsePersistentBrowserTvcWalletState(
    Object.fromEntries(CORE_KEYS.map((key) => [key, state[key]])),
  );
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.registered !== false ||
    !COMPRESSED_P256.test(state.turnkeyServicePublicKey ?? "") ||
    !validAuthority(state.tvcAuthority)
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return state as PrivateWalletState;
}

function stateRecord(ownerAddress: string): string {
  return `${STATE_RECORD_PREFIX}${ownerAddress}`;
}

function identityRecord(ownerAddress: string): string {
  return `${IDENTITY_RECORD_PREFIX}${ownerAddress}`;
}

export function loadPrivateWalletState(
  ownerAddress: string,
): Promise<PrivateWalletState | null> {
  return loadRecord(DATABASE_NAME, stateRecord(ownerAddress), (value) => {
    const state = parsePrivateWalletState(value);
    if (state && state.walletDescriptor.address !== ownerAddress) {
      throw new TvcError("StorageCorrupted");
    }
    return state;
  });
}

export function savePrivateWalletState(
  state: PrivateWalletState,
): Promise<void> {
  const parsed = parsePrivateWalletState(state);
  if (!parsed) throw new TvcError("StorageCorrupted");
  return saveRecord(
    DATABASE_NAME,
    stateRecord(parsed.walletDescriptor.address),
    parsed,
  );
}

/** Clears a recoverable descriptor/seed binding but deliberately keeps identity. */
export function clearPrivateWalletState(ownerAddress: string): Promise<void> {
  return clearRecord(DATABASE_NAME, stateRecord(ownerAddress));
}

export function loadKnownIdentity(
  ownerAddress: string,
): Promise<ShieldedIdentity | null> {
  return loadRecord(DATABASE_NAME, identityRecord(ownerAddress), (value) => {
    if (value === undefined) return null;
    const identity = parseShieldedIdentity(value);
    if (identity.solanaAddress !== ownerAddress) {
      throw new TvcError("StorageCorrupted");
    }
    return identity;
  });
}

export function saveKnownIdentity(identity: ShieldedIdentity): Promise<void> {
  const parsed = parseShieldedIdentity(identity);
  return saveRecord(
    DATABASE_NAME,
    identityRecord(parsed.solanaAddress),
    parsed,
  );
}
