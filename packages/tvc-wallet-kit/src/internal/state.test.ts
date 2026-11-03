import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearPrivateWalletState,
  loadKnownIdentity,
  loadPrivateWalletState,
  parsePrivateWalletState,
  saveKnownIdentity,
  savePrivateWalletState,
} from "./state";

const records = vi.hoisted(() => new Map<string, unknown>());
vi.mock("@zolana/tvc-wallet/browser", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@zolana/tvc-wallet/browser")>()),
  loadRecord: async (
    database: string,
    key: string,
    parse: (value: unknown) => unknown,
  ) => parse(records.get(`${database}/${key}`)),
  saveRecord: async (database: string, key: string, value: unknown) => {
    records.set(`${database}/${key}`, value);
  },
  clearRecord: async (database: string, key: string) => {
    records.delete(`${database}/${key}`);
  },
}));

const owner = "4".repeat(44);
const otherOwner = "3".repeat(44);
const authority = {
  serviceUserId: "11111111-2222-4333-8444-555555555555",
  apiKeyId: "66666666-7777-4888-8999-aaaaaaaaaaaa",
};
const descriptor = {
  version: 1,
  security_domain_id: "aa".repeat(32),
  environment: "development",
  turnkey_organization_id: "00000000-0000-0000-0000-00000000000b",
  turnkey_wallet_id: "wallet-1",
  address: owner,
  allowed_clients: [],
  provisioning_signature: "33".repeat(64),
};

function state() {
  return {
    version: 7 as const,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    walletDescriptor: descriptor,
    identity: {
      solanaAddress: owner,
      shieldedOwnerHash: "55".repeat(32),
      shieldedNullifierPublicKey: "66".repeat(32),
      shieldedViewingPublicKey: `03${"77".repeat(32)}`,
    },
    sealedSeed: { sealedSeed: "88".repeat(64) },
    registered: false as const,
    turnkeyServicePublicKey: `02${"44".repeat(32)}`,
    tvcAuthority: authority,
  };
}

describe("private wallet state", () => {
  beforeEach(() => records.clear());

  it("stores bindings per public owner", async () => {
    const value = parsePrivateWalletState(state());
    if (!value) throw new Error("fixture");
    await savePrivateWalletState(value);
    expect(await loadPrivateWalletState(owner)).toEqual(value);
    expect(await loadPrivateWalletState(otherOwner)).toBeNull();
  });

  it("keeps the known identity when a recoverable binding is cleared", async () => {
    const value = parsePrivateWalletState(state());
    if (!value?.identity) throw new Error("fixture");
    await savePrivateWalletState(value);
    await saveKnownIdentity(value.identity);

    await clearPrivateWalletState(owner);

    expect(await loadPrivateWalletState(owner)).toBeNull();
    expect(await loadKnownIdentity(owner)).toEqual(value.identity);
  });

  it("rejects registration and unrelated application state", () => {
    expect(() =>
      parsePrivateWalletState({ ...state(), registered: true }),
    ).toThrowError(/StorageCorrupted/u);
    expect(() =>
      parsePrivateWalletState({ ...state(), balances: [] }),
    ).toThrowError(/StorageCorrupted/u);
  });
});
