import { describe, expect, it } from "vitest";
import { parseStoredWallet } from "./stored.js";

const identity = {
  solanaAddress: "4".repeat(44),
  shieldedOwnerHash: "44".repeat(32),
  shieldedNullifierPublicKey: "55".repeat(32),
  shieldedViewingPublicKey: "66".repeat(33),
};
const sealedSeed = { sealedSeed: "11".repeat(64) };

describe("parseStoredWallet", () => {
  it("accepts a stored wallet, with or without its sealed seed", () => {
    expect(parseStoredWallet({ identity, sealedSeed })).toEqual({ identity, sealedSeed });
    expect(parseStoredWallet({ identity })).toEqual({ identity });
  });

  it("refuses anything else", () => {
    for (const bad of [
      undefined,
      null,
      "wallet",
      [],
      { sealedSeed },
      { identity, sealedSeed, extra: 1 },
      { identity: { ...identity, extra: 1 }, sealedSeed },
      { identity: { ...identity, solanaAddress: "short" }, sealedSeed },
      { identity: { ...identity, shieldedViewingPublicKey: "77".repeat(32) }, sealedSeed },
      { identity, sealedSeed: { sealedSeed: "not hex" } },
      { identity, sealedSeed: { sealedSeed: "AB" } },
      { identity, sealedSeed: { ...sealedSeed, extra: 1 } },
      { identity, sealedSeed: null },
    ]) {
      expect(() => parseStoredWallet(bad)).toThrowError(/StorageCorrupted/);
    }
  });
});
