import type { WalletKeys } from "@heliuslabs/zolana";
import { describe, expect, it, vi } from "vitest";
import {
  PrivateWalletSessionExpiredError,
  revocableWalletKeys,
} from "./revocable-keys";

function fakeKeys() {
  return {
    address: vi.fn(() => ({ value: "shielded" })),
    viewingPublicKeys: vi.fn(() => []),
    decrypt: vi.fn(async () => []),
    derive: vi.fn(async () => []),
    transactionKeys: vi.fn(async () => []),
    prove: vi.fn(async () => ({ proof: true })),
    proveMerge: vi.fn(async () => ({ proof: true })),
  } as unknown as WalletKeys;
}

describe("revocableWalletKeys", () => {
  it("passes the session signal into asynchronous key operations", async () => {
    const target = fakeKeys();
    const controller = new AbortController();
    const keys = revocableWalletKeys(target, controller.signal);

    await keys.decrypt([]);

    const context = vi.mocked(target.decrypt).mock.calls[0]?.[1];
    expect(context?.signal).toBe(controller.signal);
  });

  it("rejects every retained capability after invalidation", async () => {
    const target = fakeKeys();
    const controller = new AbortController();
    const keys = revocableWalletKeys(target, controller.signal);
    controller.abort();

    expect(() => keys.address()).toThrow(PrivateWalletSessionExpiredError);
    expect(() => keys.viewingPublicKeys()).toThrow(
      PrivateWalletSessionExpiredError,
    );
    await expect(keys.decrypt([])).rejects.toThrow(
      PrivateWalletSessionExpiredError,
    );
    await expect(keys.derive([])).rejects.toThrow(
      PrivateWalletSessionExpiredError,
    );
    await expect(keys.transactionKeys([])).rejects.toThrow(
      PrivateWalletSessionExpiredError,
    );
    await expect(keys.prove({} as never)).rejects.toThrow(
      PrivateWalletSessionExpiredError,
    );
    await expect(keys.proveMerge({} as never)).rejects.toThrow(
      PrivateWalletSessionExpiredError,
    );
  });
});
