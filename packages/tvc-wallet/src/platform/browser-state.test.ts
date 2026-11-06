import { describe, expect, it } from "vitest";
import { parsePersistentBrowserTvcWalletState, parseShieldedIdentity } from "./browser-state.js";

const address = "4".repeat(44);
const sealedSeed = {
  sealedSeed: "11".repeat(64),
};
const descriptor = {
  version: 2,
  security_domain_id: "aa".repeat(32),
  network: "devnet",
  turnkey_organization_id: "00000000-0000-0000-0000-00000000000b",
  turnkey_wallet_id: "wallet-1",
  address,
  allowed_clients: [],
  provisioning_signature: "33".repeat(64),
};

function baseState() {
  return {
    version: 1,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    walletDescriptor: descriptor,
    identity: null,
    sealedSeed: null,
    registered: false,
  };
}

function readyState() {
  return {
    ...baseState(),
    identity: {
      solanaAddress: address,
      shieldedOwnerHash: "55".repeat(32),
      shieldedNullifierPublicKey: "66".repeat(32),
      shieldedViewingPublicKey: `03${"77".repeat(32)}`,
    },
    sealedSeed,
    registered: true,
  };
}

describe("browser wallet state", () => {
  it("accepts descriptor-only and ready states", () => {
    expect(parsePersistentBrowserTvcWalletState(baseState())?.identity).toBeNull();
    expect(parsePersistentBrowserTvcWalletState(readyState())?.sealedSeed).toEqual(
      sealedSeed,
    );
  });

  it("rejects another state format or a descriptor of another protocol or network", () => {
    for (const state of [
      { ...baseState(), version: 2 },
      { ...baseState(), walletDescriptor: { ...descriptor, version: 1 } },
      { ...baseState(), walletDescriptor: { ...descriptor, network: "testnet" } },
    ]) {
      expect(() => parsePersistentBrowserTvcWalletState(state)).toThrowError("StorageCorrupted");
    }
    expect(
      parsePersistentBrowserTvcWalletState({
        ...baseState(),
        walletDescriptor: { ...descriptor, network: "mainnet" },
      })?.walletDescriptor.network,
    ).toBe("mainnet");
  });

  it("rejects a half-written identity sealedSeed", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({ ...readyState(), sealedSeed: null }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects a descriptor carrying any unknown key", () => {
    const widened: Record<string, unknown> = { ...descriptor };
    widened.turnkey_ring_signing_key_id = null;
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...baseState(),
        walletDescriptor: widened,
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects application state stored in the wallet record", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission: null,
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects an identity that does not match the descriptor address", () => {
    const ready = readyState();
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...ready,
        identity: { ...ready.identity, solanaAddress: "5".repeat(44) },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects a registered flag without an identity", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({ ...baseState(), registered: true }),
    ).toThrowError("StorageCorrupted");
  });

  it("passes undefined through as absent state", () => {
    expect(parsePersistentBrowserTvcWalletState(undefined)).toBeNull();
  });
});

describe("parseShieldedIdentity", () => {
  it("accepts a stored identity and rejects anything else", () => {
    const { identity } = readyState();
    expect(parseShieldedIdentity(identity)).toEqual(identity);
    for (const bad of [
      undefined,
      null,
      "identity",
      { ...identity, extra: 1 },
      { ...identity, solanaAddress: "short" },
      { ...identity, shieldedViewingPublicKey: "77".repeat(32) },
    ]) {
      expect(() => parseShieldedIdentity(bad)).toThrowError(/StorageCorrupted/);
    }
  });
});
