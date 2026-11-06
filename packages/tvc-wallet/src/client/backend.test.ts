import { describe, expect, it } from "vitest";

import type { WalletDescriptor } from "../protocol/types.js";
import { sendOperation, type TvcBackend } from "./backend.js";

const endpoint = new URL("https://devnet.helius-rpc.com/v1/private-wallet?api-key=key");
const request = { version: 1, quorum_key_id: "quorum", quorum_key_epoch: "1", ciphertext: "abcd" };
const descriptor = { address: "11111111111111111111111111111111" } as WalletDescriptor;
const backends: TvcBackend[] = [
  { kind: "gateway", endpoint },
  { kind: "enclave", endpoint: new URL("https://enclave.example") },
];

function send(backend: TvcBackend, status: number, body: string) {
  const transport = { fetch: async () => new Response(body, { status }) };
  return sendOperation(backend, request, descriptor, transport, 1_024n);
}

describe("a refused operation", () => {
  it.each(backends)("is DescriptorExpired when a 403 names it, from the gateway or the enclave ($kind)", async (backend) => {
    for (const body of [
      JSON.stringify({ error: "DescriptorExpired" }),
      JSON.stringify({ title: "Forbidden", status: 403, detail: "expired", code: "DescriptorExpired" }),
    ]) {
      await expect(send(backend, 403, body)).rejects.toMatchObject({ code: "DescriptorExpired", status: 403 });
    }
  });

  it("is rejected or unavailable otherwise", async () => {
    const [gateway] = backends as [TvcBackend];
    for (const [status, body, code] of [
      [403, JSON.stringify({ code: "InvalidDescriptor" }), "OperationRejected"],
      [403, "not json", "OperationRejected"],
      [403, "x".repeat(8_192), "OperationRejected"],
      [400, JSON.stringify({ error: "DescriptorExpired" }), "OperationRejected"],
      [424, JSON.stringify({ code: "DescriptorExpired" }), "OperationUnavailable"],
      [503, "", "OperationUnavailable"],
    ] as const) {
      await expect(send(gateway, status, body)).rejects.toMatchObject({ code, status });
    }
  });
});
