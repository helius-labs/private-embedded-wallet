import { describe, expect, it, vi } from "vitest";

import type { TvcTransport } from "../client/transport.js";
import { decodeLowerHex } from "../protocol/hex.js";
import {
  decryptProverAnswer,
  fetchAttestation,
  provingKeyName,
  proverTarget,
  sealingFor,
  submitSealed,
} from "./prover.js";
import { TvcProverPolicy, type HeldProverPolicy } from "./prover-policy.js";
import { POLICY_URL, policyFile } from "./prover-policy.testkit.js";

const HELD: HeldProverPolicy = {
  file: policyFile({ expiresAt: 1_900_000_000 }),
  version: 1,
  maxAgeSecs: 600,
  expiresAt: 1_900_000_000,
  fetchedAtMs: 0,
};

/** zolana `prover/tee/testdata/vectors.json`: an answer the Go prover sealed. */
const VECTOR = {
  responseKey: "6cdd0d870824d20a0d49e35e4fd5efc7aa1d1d02cde58c455d34d45fa3fcf93e",
  encryptedResponse:
    "458aeb3721728301508e11bda7408dfe9cf0fef050cd35727f3bb94ed23fb45538256f50928b6e8c4018acdf",
  status: 200,
  body: '{"proof":"ok"}',
};

const transfer = (circuit: string, inputs: number, outputs: number) => ({
  circuitType: circuit,
  inputs: Array.from({ length: inputs }, () => ({})),
  outputs: Array.from({ length: outputs }, () => ({})),
});
const merge = (circuit: string, inputs: number) => ({
  circuitType: circuit,
  inputs: Array.from({ length: inputs }, () => ({})),
});

describe("prover answers", () => {
  it("open the wire contract's vector", () => {
    const { status, body } = decryptProverAnswer(
      decodeLowerHex(VECTOR.responseKey),
      decodeLowerHex(VECTOR.encryptedResponse),
    );
    expect(status).toBe(VECTOR.status);
    expect(new TextDecoder().decode(body)).toBe(VECTOR.body);
  });

  it("refuse another key, a tampered byte, or a truncated answer", () => {
    const encrypted = decodeLowerHex(VECTOR.encryptedResponse);
    const tampered = encrypted.slice();
    tampered[14] = (tampered[14] ?? 0) ^ 1;
    for (const [key, bytes] of [
      [decodeLowerHex("00".repeat(32)), encrypted],
      [decodeLowerHex(VECTOR.responseKey), tampered],
      [decodeLowerHex(VECTOR.responseKey), encrypted.subarray(0, 20)],
    ] as const) {
      expect(() => decryptProverAnswer(key, bytes)).toThrowError("ProverAnswerInvalid");
    }
  });
});

describe("proving key routes", () => {
  it("name the key the enclave names", () => {
    for (const [request, key] of [
      [transfer("transfer-confidential", 2, 2), "transfer_confidential_2_2"],
      [transfer("transfer-confidential", 12, 16), "transfer_confidential_12_16"],
      [transfer("transfer-ring", 1, 2), "transfer_ring_1_2"],
      [merge("merge", 8), "merge_8_1"],
      [merge("merge", 52), "merge_52_1"],
      [merge("merge-ring", 52), "merge_ring_52_1"],
    ] as const) {
      expect(provingKeyName(request)).toBe(key);
    }
    for (const request of [
      transfer("transfer-ring-authority", 1, 2),
      { circuitType: "toString", inputs: [{}], outputs: [{}] },
      transfer("transfer-confidential", 0, 2),
      transfer("transfer-confidential", 2, 0),
      merge("merge", 53),
    ]) {
      expect(() => provingKeyName(request)).toThrowError("InvalidProverRequest");
    }
  });

  it("are the bare route below the prover URL", () => {
    expect(proverTarget("merge_8_1")).toBe("/prove/merge_8_1");
  });
});

describe("attestation", () => {
  const request = merge("merge", 8);
  const config = (response: Response) => {
    const transport: TvcTransport = { fetch: vi.fn(async () => response) };
    return {
      url: "https://gateway.test/v1/spr/?api-key=k",
      policy: new TvcProverPolicy(POLICY_URL, transport),
      transport,
    };
  };

  it("carries the prover's answer and seals the route below the prover URL", async () => {
    const prover = config(Response.json({ platform: "aws-nitro" }));
    const attested = await fetchAttestation(prover);
    const sealing = sealingFor(HELD, attested, request);
    expect(sealing.target).toBe("/prove/merge_8_1");
    expect(sealing.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(sealing.nonce).toBe(attested.nonce);
    expect(sealing.attestation).toEqual({ platform: "aws-nitro" });
    expect(sealing.policy).toBe(HELD.file);
    expect(vi.mocked(prover.transport.fetch).mock.calls[0]?.[0].pathname).toBe("/v1/spr/attestation");
  });

  it("seals the same route behind a proxy and posts to the proxy", async () => {
    const seen: URL[] = [];
    const transport: TvcTransport = {
      fetch: vi.fn(async (url: URL) => {
        seen.push(url);
        return Response.json({ code: "tee_decryption_failed" }, { status: 400 });
      }),
    };
    const proxied = {
      url: "https://app.test/api/tvc/spr/prover?session=s",
      policy: new TvcProverPolicy(POLICY_URL, transport),
      transport,
    };
    const attested = { nonce: "42".repeat(32), attestation: {}, fetchedAtMs: 0 };
    const sealing = sealingFor(HELD, attested, request);
    expect(sealing.target).toBe("/prove/merge_8_1");
    const answer = await submitSealed(proxied, {
      target: sealing.target,
      enc: "11".repeat(32),
      ciphertext: "0102",
      response_key: "22".repeat(32),
    });
    expect(answer).toEqual({ kind: "keyLost" });
    expect(`${seen[0]?.pathname}${seen[0]?.search}`).toBe(
      "/api/tvc/spr/prover/prove/merge_8_1?session=s",
    );
  });

  it("refuses an unavailable prover or an answer that is not an object", async () => {
    await expect(
      fetchAttestation(config(Response.json({ code: "attestation_busy" }, { status: 429 }))),
    ).rejects.toMatchObject({ code: "ProverAttestationUnavailable", status: 429 });
    for (const body of ["[]", "null", "not json"]) {
      await expect(fetchAttestation(config(new Response(body)))).rejects.toMatchObject({
        code: "ProverAttestationInvalid",
      });
    }
  });
});
