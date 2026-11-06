import { API_VERSION } from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import type { SealedSeed, WalletDescriptor } from "../protocol/types.js";
import type { ShieldedIdentity } from "../wallet/client.js";
import { hasOnlyKeys, isLowerHex, isSolanaAddress } from "./persisted-state.js";

const DESCRIPTOR_KEYS = [
  "version",
  "security_domain_id",
  "network",
  "turnkey_organization_id",
  "turnkey_wallet_id",
  "address",
  "allowed_clients",
  "provisioning_signature",
];
const STATE_KEYS = [
  "version",
  "clientKeyId",
  "walletDescriptor",
  "identity",
  "sealedSeed",
  "registered",
] as const;

/**
 * Enclave material only; an application stores it in its own record (see
 * `loadRecord`/`saveRecord`) beside whatever else it keeps, and parses it back
 * through `parsePersistentBrowserTvcWalletState`.
 */
export type PersistentBrowserTvcWalletState = {
  readonly version: 1;
  readonly clientKeyId: string;
  readonly walletDescriptor: WalletDescriptor;
  readonly identity: ShieldedIdentity | null;
  readonly sealedSeed: SealedSeed | null;
  readonly registered: boolean;
};

function validIdentity(value: unknown): value is ShieldedIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const identity = value as Partial<ShieldedIdentity>;
  return (
    hasOnlyKeys(value, [
      "solanaAddress",
      "shieldedOwnerHash",
      "shieldedNullifierPublicKey",
      "shieldedViewingPublicKey",
    ]) &&
    isSolanaAddress(identity.solanaAddress) &&
    isLowerHex(identity.shieldedOwnerHash, 32) &&
    isLowerHex(identity.shieldedNullifierPublicKey, 32) &&
    isLowerHex(identity.shieldedViewingPublicKey, 33)
  );
}

/**
 * A stored public identity. An application keeps one apart from the enclave
 * binding, so a later bootstrap can be pinned to it with `open({ identity })`.
 */
export function parseShieldedIdentity(value: unknown): ShieldedIdentity {
  if (!validIdentity(value)) throw new TvcError("StorageCorrupted");
  return value;
}

function validSealedSeed(value: unknown): value is SealedSeed {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const sealedSeed = value as Partial<SealedSeed>;
  return (
    hasOnlyKeys(value, ["sealedSeed"]) &&
    isLowerHex(sealedSeed.sealedSeed)
  );
}

export function parsePersistentBrowserTvcWalletState(
  value: unknown,
): PersistentBrowserTvcWalletState | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TvcError("StorageCorrupted");
  }
  const state = value as Partial<PersistentBrowserTvcWalletState>;
  const descriptor = state.walletDescriptor as Partial<WalletDescriptor> | undefined;
  const clientKeyId = state.clientKeyId ?? "";
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.version !== 1 ||
    !clientKeyId.startsWith("tvc-browser-p256-") ||
    !isLowerHex(clientKeyId.slice("tvc-browser-p256-".length), 16) ||
    !descriptor ||
    !hasOnlyKeys(descriptor, DESCRIPTOR_KEYS) ||
    descriptor.version !== API_VERSION ||
    (descriptor.network !== "devnet" && descriptor.network !== "mainnet") ||
    typeof descriptor.turnkey_wallet_id !== "string" ||
    !isLowerHex(descriptor.provisioning_signature) ||
    !isSolanaAddress(descriptor.address ?? "") ||
    (state.identity !== null && !validIdentity(state.identity)) ||
    (state.sealedSeed !== null && !validSealedSeed(state.sealedSeed)) ||
    (state.identity === null) !== (state.sealedSeed === null) ||
    typeof state.registered !== "boolean" ||
    (state.identity === null && state.registered) ||
    (state.identity !== null && state.identity.solanaAddress !== descriptor.address)
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return state as PersistentBrowserTvcWalletState;
}
