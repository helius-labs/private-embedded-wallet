import {
  ShieldedKeypair,
  Wallet,
  ViewingKey,
  type Bytes32,
  initializePoseidon,
  serializeWallet,
  walletSnapshotCipher,
  type ShieldedAddress,
} from "@heliuslabs/spr";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { SealedSeed } from "../protocol/types.js";
import type { ShieldedIdentity, TvcClient } from "./client.js";
import { TvcKeys } from "./keys.js";
import { snapshotCipher } from "./snapshot.js";

const connection = { verified: true } as unknown as VerifiedConnection;
const sealedSeed: SealedSeed = { sealedSeed: "11".repeat(64) };

function identityOf(address: ShieldedAddress): ShieldedIdentity {
  return {
    solanaAddress: address.solanaAddress(),
    shieldedOwnerHash: encodeLowerHex(address.ownerHash()),
    shieldedNullifierPublicKey: encodeLowerHex(address.nullifierPublicKey),
    shieldedViewingPublicKey: encodeLowerHex(address.viewingPublicKey.toBytes()),
  };
}

/** An enclave whose every per-transaction key is `secret`. */
function enclave(secret: Uint8Array) {
  return {
    network: "devnet",
    servicePublicKey: "",
    connectAndVerify: vi.fn(),
    bootstrap: vi.fn(),
    decrypt: vi.fn(),
    derive: vi.fn(),
    transactionKeys: vi.fn(async (_c: unknown, _k: unknown, items: readonly unknown[]) =>
      items.map(() => encodeLowerHex(secret)),
    ),
    prove: vi.fn(),
  } satisfies TvcClient;
}

function keysFor(address: ShieldedAddress, client: TvcClient): TvcKeys {
  return new TvcKeys({
    client,
    connection,
    sealedSeed,
    identity: identityOf(address),
    prover: { url: "http://prover.invalid" },
  });
}

describe("snapshotCipher", () => {
  beforeAll(() => initializePoseidon());

  it("keys the SDK envelope from a per-transaction key no transaction can have", async () => {
    const address = ShieldedKeypair.generate().shieldedAddress();
    const client = enclave(new Uint8Array(32).fill(5));
    const cipher = await snapshotCipher(keysFor(address, client));
    expect(client.transactionKeys.mock.calls[0]?.[2]).toEqual([
      {
        viewing_public_key: encodeLowerHex(address.viewingPublicKey.toBytes()),
        first_nullifier: expect.stringMatching(/^ff[0-9a-f]{62}$/),
      },
    ]);

    const snapshot = serializeWallet(new Wallet({ identity: address }));
    const sealed = await cipher.seal(snapshot);
    expect(sealed).not.toContain(address.solanaAddress());
    expect(await cipher.open(sealed)).toBe(snapshot);
    // The same enclave answer reopens it, on another device.
    expect(await (await snapshotCipher(keysFor(address, client))).open(sealed)).toBe(snapshot);
  });

  it("refuses another wallet's snapshot and one sealed under another key", async () => {
    const address = ShieldedKeypair.generate().shieldedAddress();
    const cipher = await snapshotCipher(keysFor(address, enclave(new Uint8Array(32).fill(5))));
    const otherClient = enclave(new Uint8Array(32).fill(6));

    const other = ShieldedKeypair.generate().shieldedAddress();
    const foreign = await (await snapshotCipher(keysFor(other, otherClient))).seal(
      serializeWallet(new Wallet({ identity: other })),
    );
    await expect(cipher.open(foreign)).rejects.toMatchObject({ code: "WALLET_SNAPSHOT" });

    const sealed = await cipher.seal(serializeWallet(new Wallet({ identity: address })));
    const rekeyed = await snapshotCipher(keysFor(address, otherClient));
    await expect(rekeyed.open(sealed)).rejects.toMatchObject({ code: "WALLET_SNAPSHOT" });
  });

  it("is not the local keypair's cipher", async () => {
    const keypair = ShieldedKeypair.generate();
    const address = keypair.shieldedAddress();
    const sealed = await walletSnapshotCipher(keypair).seal(
      serializeWallet(new Wallet({ identity: address })),
    );
    const cipher = await snapshotCipher(keysFor(address, enclave(new Uint8Array(32).fill(5))));
    await expect(cipher.open(sealed)).rejects.toMatchObject({ code: "WALLET_SNAPSHOT" });
  });
});


it("passes cancellation into snapshot-key loading and wipes key material after import", async () => {
  await initializePoseidon();
  const address = ShieldedKeypair.generate().shieldedAddress();
  const keys = keysFor(address, enclave(new Uint8Array(32).fill(5)));
  const key = ViewingKey.fromBytes(new Uint8Array(32).fill(5) as Bytes32);
  const material = key.secretBytes();
  vi.spyOn(key, "secretBytes").mockReturnValue(material);
  const destroy = vi.spyOn(key, "destroy");
  const request = vi.spyOn(keys, "transactionKeys").mockResolvedValueOnce([key]);
  const controller = new AbortController();
  await snapshotCipher(keys, { signal: controller.signal });
  const signal = request.mock.calls[0]?.[1]?.signal;
  expect(signal).toBeInstanceOf(AbortSignal);
  expect(material).toEqual(new Uint8Array(32));
  expect(destroy).toHaveBeenCalledOnce();
  controller.abort();
  expect(signal?.aborted).toBe(true);
});

it("discards and destroys a snapshot key returned after cancellation", async () => {
  await initializePoseidon();
  const address = ShieldedKeypair.generate().shieldedAddress();
  const keys = keysFor(address, enclave(new Uint8Array(32).fill(5)));
  const key = ViewingKey.fromBytes(new Uint8Array(32).fill(5) as Bytes32);
  const destroy = vi.spyOn(key, "destroy");
  const controller = new AbortController();
  vi.spyOn(keys, "transactionKeys").mockImplementationOnce(async () => {
    controller.abort(new Error("cancelled"));
    return [key];
  });
  await expect(snapshotCipher(keys, { signal: controller.signal })).rejects.toThrow("cancelled");
  expect(destroy).toHaveBeenCalledOnce();
});
