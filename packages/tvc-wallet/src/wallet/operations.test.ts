import { describe, expect, it, vi } from "vitest";

import type { OperationExecutionContext } from "../client/operation-executor.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { sealedSeedDigest } from "../protocol/digest.js";
import type {
  SealedSeed,
  DecryptItem,
  OperationResult,
  ProverSealing,
} from "../protocol/types.js";
import {
  checkDecrypt,
  checkDerive,
  checkProve,
  checkTransactionKeys,
  executeOperation,
} from "./operations.js";

const envelope = vi.hoisted(() => vi.fn());
vi.mock("../client/operation-executor.js", () => ({ executeOperationEnvelope: envelope }));

const sealedSeed: SealedSeed = { sealedSeed: "11".repeat(64) };
const sealedSeedDigestHex = encodeLowerHex(sealedSeedDigest(new Uint8Array(64).fill(0x11)));
const context = {
  trustVerifier: { verifyOperationAppProof: vi.fn() },
} as unknown as OperationExecutionContext;
const VIEWING = `04${"cd".repeat(32)}`;
const HASH = "22".repeat(32);

function sealing(target: string): ProverSealing {
  return {
    target,
    nonce: "42".repeat(32),
    attestation: { platform: "aws-nitro" },
    policy: {
      release: { payload: "7b7d", signatures: [{ public_key: "11".repeat(32), signature: "aa".repeat(64) }] },
      freshness: { payload: "7b7d", signatures: [{ public_key: "33".repeat(32), signature: "bb".repeat(64) }] },
    },
  };
}

const MERGE = { circuitType: "merge", inputs: [{}], userNullifierSecret: null };
const prove = { type: "Prove" as const, request: MERGE, prover: sealing("/prove/merge_1_1") };
const SEALED = {
  target: "/prove/merge_1_1",
  enc: "11".repeat(32),
  ciphertext: "0102",
  response_key: "22".repeat(32),
};

function answer(result: OperationResult, digest = sealedSeedDigestHex): void {
  envelope.mockResolvedValueOnce({ plaintext: JSON.stringify(result), sealedSeedDigest: digest });
}

const item: DecryptItem = {
  ciphertext: "ab",
  viewing_public_key: VIEWING,
  transaction_viewing_public_key: `04${"ef".repeat(32)}`,
  salt: "ef".repeat(16),
  slot_index: "1",
  label: "Transfer",
};

describe("request checks", () => {
  it("bounds every batch before signing a request", () => {
    expect(() => checkDecrypt({ type: "Decrypt", items: [] })).toThrowError("EmptyBatch");
    expect(() => checkDecrypt({ type: "Decrypt", items: Array(257).fill(item) })).toThrowError(
      "BatchTooLarge",
    );
    expect(() =>
      checkDecrypt({ type: "Decrypt", items: [{ ...item, slot_index: "4294967296" }] }),
    ).toThrowError("InvalidSlotIndex");
    expect(() =>
      checkDecrypt({ type: "Decrypt", items: [{ ...item, label: "RingDeposit" }] }),
    ).toThrowError("InvalidSlotIndex");
    expect(() =>
      checkDecrypt({ type: "Decrypt", items: [{ ...item, viewing_public_key: "02" }] }),
    ).toThrowError();

    expect(() => checkDerive({ type: "Derive", items: [] })).toThrowError("EmptyBatch");
    expect(() =>
      checkDerive({
        type: "Derive",
        items: [{ kind: "MergeDummyNullifier", first_nullifier: HASH, slot_index: "256" }],
      }),
    ).toThrowError("InvalidSlotIndex");
    expect(
      checkDerive({
        type: "Derive",
        items: [
          { kind: "Nullifier", utxo_hash: HASH, blinding: HASH },
          { kind: "MergePrivateTxBlinding", first_nullifier: HASH },
          { kind: "MergeOutputKey", first_nullifier: HASH },
        ],
      }).items,
    ).toHaveLength(3);

    expect(() => checkTransactionKeys({ type: "TransactionKeys", items: [] })).toThrowError(
      "EmptyBatch",
    );
    expect(() =>
      checkTransactionKeys({
        type: "TransactionKeys",
        items: [{ viewing_public_key: VIEWING, first_nullifier: "22" }],
      }),
    ).toThrowError();
  });

  it("sends the prover only a request the enclave has something to fill in", () => {
    const open = {
      circuitType: "transfer-confidential",
      inputs: [{ isDummy: "0x0", nullifierSecret: null }],
      outputs: [{}, {}],
    };
    const prover = sealing("/prove/transfer_confidential_1_2");
    expect(checkProve({ type: "Prove", request: open, prover }).request).toBe(open);
    for (const request of [
      { ...open, circuitType: "custom-ring" },
      { ...open, inputs: [] },
      { ...open, inputs: Array(53).fill(open.inputs[0]) },
      { ...open, inputs: [{ isDummy: "0x0", nullifierSecret: "0x1" }] },
      { circuitType: "merge", inputs: [{}], userNullifierSecret: "0x1" },
    ]) {
      expect(() => checkProve({ type: "Prove", request, prover })).toThrowError(
        "InvalidProverRequest",
      );
    }
    expect(checkProve(prove).request["circuitType"]).toBe("merge");
  });

  it("seals only to the request's proving key route", () => {
    expect(checkProve({ ...prove, prover: sealing("/prove/merge_1_1") }).prover.target).toBe(
      "/prove/merge_1_1",
    );
    for (const target of [
      "/v1/spr/prove/merge_1_1",
      "/prove/merge_8_1",
      "/prove/merge_1_1?jobId=1",
      "/prove/merge_1_1/",
      "//prove/merge_1_1",
      "prove/merge_1_1",
    ]) {
      expect(() => checkProve({ ...prove, prover: sealing(target) }), target).toThrowError(
        "InvalidProverRequest",
      );
    }
    expect(() =>
      checkProve({ ...prove, prover: { ...sealing("/prove/merge_1_1"), nonce: "42" } }),
    ).toThrowError("InvalidHex");
    expect(() =>
      checkProve({
        ...prove,
        prover: { ...sealing("/prove/merge_1_1"), extra: 1 } as unknown as ProverSealing,
      }),
    ).toThrowError("UnknownJsonField");
  });
});

describe("result checks", () => {
  const derive = {
    type: "Derive" as const,
    items: [{ kind: "MergeOutputBlinding" as const, first_nullifier: HASH }],
  };

  it("returns a result that names the requested operation and sealed seed", async () => {
    answer({ type: "Derive", values: ["ab".repeat(32)] });
    await expect(executeOperation(context, derive, sealedSeed)).resolves.toEqual({
      type: "Derive",
      values: ["ab".repeat(32)],
    });
  });

  it("passes the caller's abort signal down to the envelope exchange", async () => {
    answer({ type: "Derive", values: ["ab".repeat(32)] });
    const controller = new AbortController();
    await executeOperation(context, derive, sealedSeed, { signal: controller.signal });
    expect(envelope).toHaveBeenLastCalledWith(context, derive, sealedSeed, expect.any(AbortSignal));
    const signal = envelope.mock.lastCall?.[3] as AbortSignal;
    controller.abort();
    expect(signal.aborted).toBe(true);
  });

  it("rejects a proof over another sealed seed", async () => {
    answer({ type: "Derive", values: ["ab".repeat(32)] }, "00".repeat(32));
    await expect(executeOperation(context, derive, sealedSeed)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });
  });

  it("surfaces an enclave failure stage and refuses a result for another operation", async () => {
    answer({ type: "Failure", operation: "Prove", stage: "Prover" });
    await expect(executeOperation(context, prove, sealedSeed)).rejects.toMatchObject({
      name: "TvcOperationError",
      code: "OperationFailed",
      operation: "Prove",
      stage: "Prover",
    });
    answer({ type: "Failure", operation: "Prove", stage: "Elsewhere" } as unknown as OperationResult);
    await expect(executeOperation(context, prove, sealedSeed)).rejects.toMatchObject({
      code: "UnsupportedVersion",
    });

    answer({ type: "Derive", values: ["ab".repeat(32)] });
    await expect(
      executeOperation(context, { type: "Decrypt", items: [item] }, sealedSeed),
    ).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
  });

  it("requires one answer per item, each of the promised width", async () => {
    const decrypt = { type: "Decrypt" as const, items: [item, { ...item, slot_index: "2" }] };
    answer({ type: "Decrypt", plaintexts: ["0102", "03"] });
    await expect(executeOperation(context, decrypt, sealedSeed)).resolves.toMatchObject({
      plaintexts: ["0102", "03"],
    });
    answer({ type: "Decrypt", plaintexts: ["0102"] });
    await expect(executeOperation(context, decrypt, sealedSeed)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });
    answer({ type: "Derive", values: ["ab".repeat(31)] });
    await expect(executeOperation(context, derive, sealedSeed)).rejects.toMatchObject({
      code: "InvalidHex",
    });
    answer({ type: "TransactionKeys", secrets: ["ab".repeat(32)] });
    await expect(
      executeOperation(
        context,
        { type: "TransactionKeys", items: [{ viewing_public_key: VIEWING, first_nullifier: HASH }] },
        sealedSeed,
      ),
    ).resolves.toMatchObject({ secrets: ["ab".repeat(32)] });
  });

  it("returns a request sealed for the asked target and rejects any other shape", async () => {
    answer({ type: "Prove", sealed: SEALED });
    await expect(executeOperation(context, prove, sealedSeed)).resolves.toEqual({
      type: "Prove",
      sealed: SEALED,
    });
    for (const [sealed, code] of [
      [{ ...SEALED, target: "/prove/merge_8_1" }, "ReleaseBindingMismatch"],
      [{ ...SEALED, ciphertext: "" }, "ReleaseBindingMismatch"],
      [{ ...SEALED, enc: "11" }, "InvalidHex"],
      [{ ...SEALED, response_key: "22".repeat(31) }, "InvalidHex"],
      [{ ...SEALED, proof: {} }, "UnknownJsonField"],
    ] as const) {
      answer({ type: "Prove", sealed } as unknown as OperationResult);
      await expect(executeOperation(context, prove, sealedSeed)).rejects.toMatchObject({ code });
    }
  });
});
