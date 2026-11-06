import { ShieldedKeypair, initializePoseidon, type Bytes16, type Bytes32 } from "@heliuslabs/spr";
import type { MergeInputs, ProverInputs } from "@heliuslabs/spr/client";
import { gcm } from "@noble/ciphers/aes";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { SprEmbeddedWalletTransport } from "../client/transport.js";
import { SprEmbeddedWalletError, SprEmbeddedWalletOperationError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ProverSealing, SealedProverRequest, SealedSeed } from "../protocol/types.js";
import type { ShieldedIdentity } from "./client.js";
import { EnclaveKeys, type SprEmbeddedWalletEnclave } from "./keys.js";
import { SprEmbeddedWalletProverPolicy } from "./prover-policy.js";
import { POLICY_URL, policyFile } from "./prover-policy.testkit.js";
import type { OperationOptions } from "./operations.js";

const encoders = vi.hoisted(() => ({
  proverRequestBody: vi.fn(),
  mergeProverRequestBody: vi.fn(),
}));
vi.mock("@heliuslabs/spr/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@heliuslabs/spr/client")>()),
  proverRequestBody: encoders.proverRequestBody,
  mergeProverRequestBody: encoders.mergeProverRequestBody,
}));

const sealedSeed: SealedSeed = { sealedSeed: "11".repeat(64) };
const ZERO_PROOF = {
  proof: {
    ar: ["0x0", "0x0"],
    bs: [
      ["0x0", "0x0"],
      ["0x0", "0x0"],
    ],
    krs: ["0x0", "0x0"],
  },
};

function bytes(value: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(value);
}

const PROVER_URL = "https://gateway.test/v1/spr?api-key=k";
const POLICY = policyFile({ expiresAt: 1_900_000_000 });
const RESPONSE_KEY = "33".repeat(32);

function sealedFor(target: string): SealedProverRequest {
  return { target, enc: "11".repeat(32), ciphertext: "0102", response_key: RESPONSE_KEY };
}

/** An answer as the attested prover seals it under the response key. */
function sealedAnswer(status: number, body: unknown): Uint8Array<ArrayBuffer> {
  const plaintext = new Uint8Array([status >> 8, status & 0xff, ...new TextEncoder().encode(JSON.stringify(body))]);
  const nonce = bytes(7, 12);
  return new Uint8Array([...nonce, ...gcm(decodeLowerHex(RESPONSE_KEY), nonce).encrypt(plaintext)]);
}

/**
 * The prover side of a proof: attestation answers, then the sealed answers in
 * `answers` order. Records every request it sees.
 */
function proverTransport(answers: readonly Response[] = []) {
  const queue = [...answers];
  const seen: { method: string; url: URL; headers: Headers }[] = [];
  const transport: SprEmbeddedWalletTransport = {
    fetch: vi.fn(async (url: URL, init?: RequestInit) => {
      seen.push({ method: init?.method ?? "GET", url, headers: new Headers(init?.headers) });
      if (url.href === POLICY_URL) return Response.json(POLICY);
      if (url.pathname.endsWith("/attestation")) {
        return Response.json({ platform: "aws-nitro", hpke_public_key: "44".repeat(32) });
      }
      return (
        queue.shift() ??
        new Response(sealedAnswer(200, ZERO_PROOF), { headers: { "Spr-Tee": "v1" } })
      );
    }),
  };
  return { transport, seen };
}

function fixture(answers: readonly Response[] = []) {
  const keypair = ShieldedKeypair.generate();
  const address = keypair.shieldedAddress();
  const identity: ShieldedIdentity = {
    solanaAddress: address.solanaAddress(),
    shieldedOwnerHash: encodeLowerHex(address.ownerHash()),
    shieldedNullifierPublicKey: encodeLowerHex(address.nullifierPublicKey),
    shieldedViewingPublicKey: encodeLowerHex(address.viewingPublicKey.toBytes()),
  };
  const enclave = {
    decrypt: vi.fn(async (_k: unknown, items: readonly unknown[]) =>
      items.map((_, index) => encodeLowerHex(bytes(index + 1, 3))),
    ),
    derive: vi.fn(async (_k: unknown, items: readonly unknown[]) =>
      items.map((_, index) => encodeLowerHex(bytes(index + 1))),
    ),
    transactionKeys: vi.fn(async (_k: unknown, items: readonly unknown[]) =>
      items.map((_, index) => encodeLowerHex(bytes(index + 1))),
    ),
    prove: vi.fn(async (_k: unknown, _r: unknown, prover: ProverSealing) =>
      sealedFor(prover.target),
    ),
  } satisfies SprEmbeddedWalletEnclave;
  const { transport, seen } = proverTransport(answers);
  return {
    address,
    identity,
    enclave,
    seen,
    keys: new EnclaveKeys({
      enclave,
      sealedSeed,
      identity,
      prover: { url: PROVER_URL, policy: new SprEmbeddedWalletProverPolicy(POLICY_URL, transport), transport },
    }),
  };
}

describe("SprEmbeddedWalletKeys", () => {
  beforeAll(() => initializePoseidon());

  it("is the bootstrapped identity, holds its one viewing key, and stores what reopens it", () => {
    const { address, identity, keys } = fixture();
    expect(keys.address().toBytes()).toEqual(address.toBytes());
    expect(keys.viewingPublicKeys().map((key) => key.toBytes())).toEqual([
      address.viewingPublicKey.toBytes(),
    ]);
    expect(keys.stored).toEqual({ identity, sealedSeed });
    expect(Object.isFrozen(keys.stored.identity)).toBe(true);
    const { enclave } = fixture();
    expect(
      () =>
        new EnclaveKeys({
          enclave,
          sealedSeed,
          identity: { ...identity, shieldedOwnerHash: "00".repeat(32) },
          prover: { url: PROVER_URL, policy: new SprEmbeddedWalletProverPolicy(POLICY_URL) },
        }),
    ).toThrowError(/ShieldedIdentityChanged/);
  });

  it("puts every SDK request on the wire in the enclave's terms", async () => {
    const { address, keys, enclave } = fixture();
    const other = ShieldedKeypair.generate().viewingPublicKey();
    const plaintexts = await keys.decrypt([
      {
        ciphertext: bytes(9, 4),
        viewingPublicKey: address.viewingPublicKey,
        txViewingPublicKey: other,
        salt: bytes(5, 16) as Bytes16,
        slotIndex: 3,
        label: "transfer",
      },
      {
        ciphertext: bytes(8, 4),
        viewingPublicKey: address.viewingPublicKey,
        txViewingPublicKey: other,
        salt: bytes(5, 16) as Bytes16,
        slotIndex: 0,
        label: "ringDeposit",
      },
    ]);
    expect(enclave.decrypt).toHaveBeenCalledWith(sealedSeed, [
      {
        ciphertext: "09090909",
        viewing_public_key: encodeLowerHex(address.viewingPublicKey.toBytes()),
        transaction_viewing_public_key: encodeLowerHex(other.toBytes()),
        salt: "05".repeat(16),
        slot_index: "3",
        label: "Transfer",
      },
      expect.objectContaining({ ciphertext: "08080808", slot_index: "0", label: "RingDeposit" }),
    ], {});
    expect(plaintexts).toEqual([bytes(1, 3), bytes(2, 3)]);

    const values = await keys.derive([
      { kind: "nullifier", utxoHash: bytes(1) as Bytes32, blinding: bytes(2) as Bytes32 },
      { kind: "mergeDummyNullifier", firstNullifier: bytes(3) as Bytes32, slotIndex: 7 },
      { kind: "mergeOutputBlinding", firstNullifier: bytes(3) as Bytes32 },
      { kind: "mergePrivateTxBlinding", firstNullifier: bytes(3) as Bytes32 },
      { kind: "mergeOutputKey", firstNullifier: bytes(3) as Bytes32 },
    ]);
    expect(enclave.derive).toHaveBeenCalledWith(sealedSeed, [
      { kind: "Nullifier", utxo_hash: "01".repeat(32), blinding: "02".repeat(32) },
      { kind: "MergeDummyNullifier", first_nullifier: "03".repeat(32), slot_index: "7" },
      { kind: "MergeOutputBlinding", first_nullifier: "03".repeat(32) },
      { kind: "MergePrivateTxBlinding", first_nullifier: "03".repeat(32) },
      { kind: "MergeOutputKey", first_nullifier: "03".repeat(32) },
    ], {});
    expect(values).toEqual([bytes(1), bytes(2), bytes(3), bytes(4), bytes(5)]);

    const [txKey] = await keys.transactionKeys([
      { viewingPublicKey: address.viewingPublicKey, firstNullifier: bytes(4) as Bytes32 },
    ]);
    expect(enclave.transactionKeys).toHaveBeenCalledWith(sealedSeed, [
      {
        viewing_public_key: encodeLowerHex(address.viewingPublicKey.toBytes()),
        first_nullifier: "04".repeat(32),
      },
    ], {});
    // The enclave answered with the secret 0x01..01; the key is that secret,
    // clamped as every X25519 viewing secret is.
    const clamped = bytes(1);
    clamped[0] = 0x00;
    clamped[31] = 0x41;
    expect(txKey?.secretBytes()).toEqual(clamped);
  });

  it("splits a long batch and keeps the answers in request order", async () => {
    const { keys, enclave } = fixture();
    const values = await keys.derive(
      Array.from({ length: 300 }, (_, index) => ({
        kind: "mergeOutputBlinding" as const,
        firstNullifier: bytes(index % 256) as Bytes32,
      })),
    );
    expect(enclave.derive).toHaveBeenCalledTimes(2);
    expect(enclave.derive.mock.calls[0]?.[1]).toHaveLength(256);
    expect(enclave.derive.mock.calls[1]?.[1]).toHaveLength(44);
    expect(values).toHaveLength(300);
    expect(values[256]).toEqual(bytes(1));
  });

  it("splits on the byte ceiling, preserves order, and propagates other failures", async () => {
    const { keys, enclave } = fixture();
    enclave.derive.mockImplementation(async (_k, items) => {
      if (items.length > 2) throw new SprEmbeddedWalletError("RequestTooLarge");
      return items.map((item) => (item as { first_nullifier: string }).first_nullifier);
    });
    const requests = Array.from({ length: 7 }, (_, index) => ({
      kind: "mergeOutputBlinding" as const,
      firstNullifier: bytes(index) as Bytes32,
    }));
    expect(await keys.derive(requests)).toEqual(requests.map((item) => item.firstNullifier));
    expect(enclave.derive.mock.calls.map((call) => call[1].length)).toEqual([7, 3, 1, 2, 4, 2, 2]);

    for (const code of ["RequestTooLarge", "OperationRejected"] as const) {
      enclave.derive.mockClear();
      enclave.derive.mockRejectedValue(new SprEmbeddedWalletError(code));
      await expect(keys.derive(requests.slice(0, 1))).rejects.toMatchObject({ code });
      expect(enclave.derive).toHaveBeenCalledTimes(1);
    }
    enclave.derive.mockClear();
    await expect(keys.derive(requests)).rejects.toMatchObject({ code: "OperationRejected" });
    expect(enclave.derive).toHaveBeenCalledTimes(1);
  });

  it("seals the SDK's open prover body to the attested prover and opens its answer", async () => {
    const { keys, enclave, seen } = fixture();
    const body = { circuitType: "merge", inputs: [{}], userNullifierSecret: null };
    encoders.mergeProverRequestBody.mockReturnValueOnce(body);
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    const proof = await keys.proveMerge(inputs);
    expect(encoders.mergeProverRequestBody).toHaveBeenCalledWith(inputs);
    expect(enclave.prove).toHaveBeenCalledWith(
      sealedSeed,
      body,
      {
        target: "/prove/merge_1_1",
        nonce: expect.stringMatching(/^[0-9a-f]{64}$/),
        attestation: { platform: "aws-nitro", hpke_public_key: "44".repeat(32) },
        policy: POLICY,
      },
      {},
    );
    expect(proof.a).toHaveLength(64);

    // The policy file comes first; the attestation carries the nonce the
    // enclave checks; the sealed request goes to its target with the base
    // URL's API key and the TEE headers.
    const [policy, attest, submit] = seen;
    const nonce = enclave.prove.mock.lastCall?.[2].nonce;
    expect(policy?.url.href).toBe(POLICY_URL);
    expect(attest?.url.pathname).toBe("/v1/spr/attestation");
    expect(attest?.url.searchParams.get("nonce")).toBe(nonce);
    expect(attest?.url.searchParams.get("api-key")).toBe("k");
    expect(submit?.method).toBe("POST");
    expect(`${submit?.url.pathname}${submit?.url.search}`).toBe("/v1/spr/prove/merge_1_1?api-key=k");
    expect(submit?.headers.get("Spr-Tee")).toBe("v1");
    expect(submit?.headers.get("Spr-Tee-Enc")).toBe("11".repeat(32));

    const transfer = {
      circuitType: "transfer-confidential",
      inputs: [{ nullifierSecret: null }],
      outputs: [{}, {}],
    };
    encoders.proverRequestBody.mockReturnValueOnce(transfer);
    await keys.prove({ circuit: "transfer" } as unknown as ProverInputs);
    expect(enclave.prove).toHaveBeenLastCalledWith(
      sealedSeed,
      transfer,
      expect.objectContaining({ target: "/prove/transfer_confidential_1_2" }),
      {},
    );
  });

  it("downloads the policy, attests and seals again once when the prover lost its key", async () => {
    const lost = () => Response.json({ code: "tee_decryption_failed" }, { status: 400 });
    const { keys, enclave, seen } = fixture([lost()]);
    encoders.mergeProverRequestBody.mockReturnValue({
      circuitType: "merge",
      inputs: [{}],
      userNullifierSecret: null,
    });
    const proof = await keys.proveMerge({ circuit: "merge" } as unknown as MergeInputs);
    expect(proof.a).toHaveLength(64);
    expect(enclave.prove).toHaveBeenCalledTimes(2);
    expect(seen.filter(({ url }) => url.pathname.endsWith("/attestation"))).toHaveLength(2);
    expect(seen.filter(({ url }) => url.href === POLICY_URL)).toHaveLength(2);

    const twice = fixture([lost(), lost()]);
    await expect(
      twice.keys.proveMerge({ circuit: "merge" } as unknown as MergeInputs),
    ).rejects.toMatchObject({ code: "ProverKeyLost" });
  });

  it("reuses one attestation for the policy's max age", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
    try {
      const { keys, enclave, seen } = fixture();
      encoders.mergeProverRequestBody.mockReturnValue({
        circuitType: "merge",
        inputs: [{}],
        userNullifierSecret: null,
      });
      const inputs = { circuit: "merge" } as unknown as MergeInputs;
      const attestations = () => seen.filter(({ url }) => url.pathname.endsWith("/attestation"));
      await keys.proveMerge(inputs);
      now.mockReturnValue(1_800_000_000_000 + 599_000);
      await keys.proveMerge(inputs);
      expect(attestations()).toHaveLength(1);
      const [first, second] = enclave.prove.mock.calls.map((call) => call[2].nonce);
      expect(second).toBe(first);

      now.mockReturnValue(1_800_000_000_000 + 600_000);
      await keys.proveMerge(inputs);
      expect(attestations()).toHaveLength(2);
      expect(enclave.prove.mock.lastCall?.[2].nonce).not.toBe(first);
    } finally {
      now.mockRestore();
    }
  });

  it("fetches a fresh policy and attestation once when the enclave refuses them", async () => {
    const { keys, enclave, seen } = fixture();
    encoders.mergeProverRequestBody.mockReturnValue({
      circuitType: "merge",
      inputs: [{}],
      userNullifierSecret: null,
    });
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    await keys.proveMerge(inputs);
    enclave.prove.mockRejectedValueOnce(new SprEmbeddedWalletOperationError("Prove", "Prover"));
    await keys.proveMerge(inputs);
    expect(seen.filter(({ url }) => url.pathname.endsWith("/attestation"))).toHaveLength(2);
    expect(seen.filter(({ url }) => url.href === POLICY_URL)).toHaveLength(2);
    expect(enclave.prove).toHaveBeenCalledTimes(3);

    // Only the structured stage counts, never an error's text.
    const plain = fixture();
    plain.enclave.prove.mockRejectedValueOnce(new SprEmbeddedWalletError("OperationFailed", "Prover"));
    await expect(plain.keys.proveMerge(inputs)).rejects.toMatchObject({ code: "OperationFailed" });
    expect(plain.enclave.prove).toHaveBeenCalledOnce();

    // A fresh policy and attestation the enclave refuses are the caller's error.
    const refused = fixture();
    refused.enclave.prove.mockRejectedValue(new SprEmbeddedWalletOperationError("Prove", "Prover"));
    await expect(refused.keys.proveMerge(inputs)).rejects.toMatchObject({ code: "OperationFailed", stage: "Prover" });
    expect(refused.enclave.prove).toHaveBeenCalledTimes(2);
  });

  it("refuses an unencrypted success and surfaces the prover's refusal", async () => {
    encoders.mergeProverRequestBody.mockReturnValue({
      circuitType: "merge",
      inputs: [{}],
      userNullifierSecret: null,
    });
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    const plain = fixture([Response.json(ZERO_PROOF)]);
    await expect(plain.keys.proveMerge(inputs)).rejects.toMatchObject({
      code: "ProverAnswerUnencrypted",
    });
    const refused = fixture([
      new Response(sealedAnswer(422, { code: "bad_witness" }), { headers: { "Spr-Tee": "v1" } }),
    ]);
    await expect(refused.keys.proveMerge(inputs)).rejects.toMatchObject({ code: "ProverRefused" });
    const tampered = sealedAnswer(200, ZERO_PROOF);
    tampered[20] = (tampered[20] ?? 0) ^ 1;
    const forged = fixture([new Response(tampered, { headers: { "Spr-Tee": "v1" } })]);
    await expect(forged.keys.proveMerge(inputs)).rejects.toMatchObject({
      code: "ProverAnswerInvalid",
    });
  });

  it.each([502, 503, 504])("surfaces HTTP %s without repeating a proof", async (status) => {
    encoders.mergeProverRequestBody.mockReturnValue({
      circuitType: "merge",
      inputs: [{}],
      userNullifierSecret: null,
    });
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    for (const encrypted of [false, true]) {
      const response = encrypted
        ? new Response(sealedAnswer(status, { code: "unavailable" }), {
            headers: { "Spr-Tee": "v1", "Retry-After": "3" },
          })
        : new Response("upstream unavailable", { status, headers: { "Retry-After": "3" } });
      const { keys, enclave, seen } = fixture([response]);
      await expect(keys.proveMerge(inputs)).rejects.toMatchObject({
        name: "SprEmbeddedWalletHttpError", code: "ProverRefused", status, retryAfter: "3",
      });
      expect(enclave.prove).toHaveBeenCalledTimes(1);
      expect(seen.filter(({ url }) => url.pathname.includes("/prove/"))).toHaveLength(1);
    }
  });

  it("hands the SDK's request context to every batch of a key call", async () => {
    const { address, keys, enclave } = fixture();
    const controller = new AbortController();
    const context = { signal: controller.signal, timeoutMs: 1_000 };

    await keys.derive(
      Array.from({ length: 300 }, (_, index) => ({
        kind: "mergeOutputBlinding" as const,
        firstNullifier: bytes(index % 256) as Bytes32,
      })),
      context,
    );
    // One combined signal per SDK request: the deadline covers both batches.
    const [first, second] = enclave.derive.mock.calls.map(
      (call) => (call.at(2) as OperationOptions | undefined)?.signal,
    );
    expect(first).toBeInstanceOf(AbortSignal);
    expect(second).toBe(first);

    await keys.decrypt([], context);
    await keys.transactionKeys(
      [{ viewingPublicKey: address.viewingPublicKey, firstNullifier: bytes(4) as Bytes32 }],
      { signal: controller.signal },
    );
    expect(enclave.transactionKeys).toHaveBeenLastCalledWith(sealedSeed, expect.anything(), {
      signal: controller.signal,
    });
  });

  it("hands the SDK's cancellation and deadline to the enclave call", async () => {
    const { keys, enclave } = fixture();
    encoders.proverRequestBody.mockReturnValue({
      circuitType: "transfer-confidential",
      inputs: [{ nullifierSecret: null }],
      outputs: [{}],
    });
    const inputs = { circuit: "transfer" } as unknown as ProverInputs;

    const controller = new AbortController();
    await keys.prove(inputs, { signal: controller.signal });
    expect(enclave.prove).toHaveBeenLastCalledWith(
      sealedSeed,
      expect.anything(),
      expect.anything(),
      { signal: controller.signal },
    );

    await keys.prove(inputs, { signal: controller.signal, timeoutMs: 1_000 });
    const options = enclave.prove.mock.lastCall?.at(3) as OperationOptions | undefined;
    expect(options?.signal).toBeInstanceOf(AbortSignal);
    expect(options?.signal?.aborted).toBe(false);
    controller.abort();
    expect(options?.signal?.aborted).toBe(true);
  });
});
