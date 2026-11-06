import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/p256";
import { afterEach, describe, expect, it, vi } from "vitest";
import { signP256Prehash } from "../crypto/p256.js";
import { qosDecrypt } from "../crypto/qos.js";
import { clientKeyIdFor } from "../protocol/digest.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { OperationRequest, ServiceInfo, WalletDescriptor, WalletGrant } from "../protocol/types.js";
import { executeOperation } from "../wallet/operations.js";
import { executeOperationEnvelope, type OperationExecutionContext } from "./operation-executor.js";

function fixture() {
  const secret = new Uint8Array(32).fill(1);
  const publicKey = p256.getPublicKey(secret, false);
  const { descriptor } = JSON.parse(readFileSync(new URL(
    "../../../../crates/protocol/fixtures/descriptor-digest.json", import.meta.url,
  ), "utf8")) as { descriptor: WalletDescriptor };
  descriptor.allowed_clients = [{ client_public_key: encodeLowerHex(publicKey), allowed_operations: ["Decrypt"] }];
  const { grant } = JSON.parse(readFileSync(new URL(
    "../../../../crates/protocol/fixtures/wallet-grant-digest.json", import.meta.url,
  ), "utf8")) as { grant: WalletGrant };
  const info = {
    version: 2, network: "devnet", security_domain_id: "00".repeat(32),
    release_id: "test-é", manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32),
    quorum_public_key: encodeLowerHex(publicKey) + encodeLowerHex(publicKey),
    quorum_key_id: "quorum-é", quorum_key_epoch: "1", ephemeral_public_key: "",
    supported_operations: ["Decrypt"], max_encrypted_request_bytes: "262144",
    max_encrypted_response_bytes: "262144", proof_type: "",
  } satisfies ServiceInfo;
  const sign = vi.fn(async ({ clientAuthDigest }: { clientAuthDigest: Uint8Array }) => signP256Prehash(secret, clientAuthDigest));
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: OperationExecutionContext = {
    backend: { kind: "enclave", endpoint: new URL("https://example.invalid"), walletGrant: async () => grant },
    info, transport: { fetch },
    operations: {
      walletDescriptor: descriptor,
      authorizer: { clientKeyId: clientKeyIdFor(publicKey), authorizeTvcRequest: sign },
    },
    releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {} },
  };
  const item = {
    ciphertext: "ab".repeat(128), viewing_public_key: "04" + "11".repeat(32),
    transaction_viewing_public_key: "04" + "22".repeat(32), salt: "33".repeat(16),
    slot_index: "1", label: "Transfer" as const,
  };
  return { context, item, sign, fetch, secret, grant };
}

describe("wallet grant", () => {
  it("travels beside the ciphertext, unchanged", async () => {
    const { context, item, fetch, grant } = fixture();
    await expect(executeOperationEnvelope(context, { type: "Decrypt", items: [item] }, { sealedSeed: "aa".repeat(8) }))
      .rejects.toMatchObject({ code: "OperationUnavailable" });
    const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as { wallet_grant: WalletGrant };
    expect(body.wallet_grant).toEqual(grant);
  });

  it("is asked for on every request", async () => {
    const { context, item, grant } = fixture();
    const walletGrant = vi.fn(async () => grant);
    const renewing: OperationExecutionContext = {
      ...context,
      backend: { kind: "enclave", endpoint: new URL("https://example.invalid"), walletGrant },
    };
    const operation = { type: "Decrypt" as const, items: [item] };
    await expect(executeOperationEnvelope(renewing, operation, { sealedSeed: "aa".repeat(8) })).rejects.toThrow();
    await expect(executeOperationEnvelope(renewing, operation, { sealedSeed: "aa".repeat(8) })).rejects.toThrow();
    expect(walletGrant).toHaveBeenCalledTimes(2);
  });
});

it("refuses a descriptor for another network before signing", async () => {
  const { context, item, sign, fetch } = fixture();
  const mainnet: OperationExecutionContext = {
    ...context,
    operations: {
      ...context.operations,
      walletDescriptor: { ...context.operations.walletDescriptor, network: "mainnet" },
    },
  };
  await expect(executeOperationEnvelope(mainnet, { type: "Decrypt", items: [item] }))
    .rejects.toMatchObject({ code: "NetworkMismatch" });
  expect(sign).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});

describe("through a gateway", () => {
  function gatewayFixture() {
    const base = fixture();
    const context: OperationExecutionContext = {
      ...base.context,
      backend: { kind: "gateway", endpoint: new URL("https://gateway.example/v1/private-wallet?api-key=key") },
    };
    return { ...base, context };
  }

  it("sends the descriptor beside a request without a grant", async () => {
    const { context, item, fetch } = gatewayFixture();
    await expect(executeOperationEnvelope(context, { type: "Decrypt", items: [item] }, { sealedSeed: "aa".repeat(8) }))
      .rejects.toMatchObject({ code: "OperationUnavailable" });
    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://gateway.example/v1/private-wallet/operations?api-key=key");
    const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as {
      descriptor: WalletDescriptor;
      request: Record<string, unknown>;
    };
    expect(Object.keys(body).sort()).toEqual(["descriptor", "request"]);
    expect(body.descriptor).toEqual(context.operations.walletDescriptor);
    expect(Object.keys(body.request).sort()).toEqual(["ciphertext", "quorum_key_epoch", "quorum_key_id", "version"]);
  });

  it("refuses an answer that is not exactly the response and its Boot Proof", async () => {
    const { context, item, fetch } = gatewayFixture();
    fetch.mockResolvedValueOnce(new Response(JSON.stringify({ response: {}, bootProof: {}, extra: 1 }), { status: 200 }));
    await expect(executeOperationEnvelope(context, { type: "Decrypt", items: [item] }, { sealedSeed: "aa".repeat(8) }))
      .rejects.toMatchObject({ code: "UnknownJsonField" });
  });

  it("reports a gateway's 424 as unavailable and its 403 as rejected", async () => {
    const { context, item, fetch } = gatewayFixture();
    const operation = { type: "Decrypt" as const, items: [item] };
    fetch.mockResolvedValueOnce(new Response(null, { status: 424 }));
    await expect(executeOperationEnvelope(context, operation)).rejects.toMatchObject({ code: "OperationUnavailable" });
    fetch.mockResolvedValueOnce(new Response(null, { status: 403 }));
    await expect(executeOperationEnvelope(context, operation)).rejects.toMatchObject({ code: "OperationRejected" });
  });

  it("leaves room in the request budget for the grant the gateway adds", async () => {
    const direct = fixture();
    const { context, item, fetch } = gatewayFixture();
    const operation = { type: "Decrypt" as const, items: [item] };
    await expect(executeOperationEnvelope(direct.context, operation)).rejects.toMatchObject({ code: "OperationUnavailable" });
    const directRequest = JSON.parse(direct.fetch.mock.calls[0]?.[1]?.body as string) as Record<string, unknown>;
    delete directRequest.wallet_grant;
    context.info.max_encrypted_request_bytes = String(new TextEncoder().encode(JSON.stringify(directRequest)).length);
    await expect(executeOperationEnvelope(context, operation)).rejects.toMatchObject({ code: "RequestTooLarge" });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("serialized operation request budget", () => {
  it("rejects 256 128-byte ciphertexts locally before authorization or fetch", async () => {
    const { context, item, sign, fetch } = fixture();
    await expect(executeOperationEnvelope(context, { type: "Decrypt", items: Array(256).fill(item) }))
      .rejects.toMatchObject({ code: "RequestTooLarge" });
    expect(sign).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts the exact UTF-8 envelope limit and rejects one byte less", async () => {
    const { context, item, sign, fetch, secret } = fixture();
    const operation = { type: "Decrypt" as const, items: [item] };
    const send = () => executeOperationEnvelope(context, operation, { sealedSeed: "aa".repeat(128) });
    await expect(send()).rejects.toMatchObject({ code: "OperationUnavailable" });
    const body = fetch.mock.calls[0]?.[1]?.body as string;
    const request = JSON.parse(new TextDecoder().decode(qosDecrypt(secret,
      decodeLowerHex((JSON.parse(body) as { ciphertext: string }).ciphertext)))) as OperationRequest;
    expect(request.operation).toEqual(operation);
    const limit = new TextEncoder().encode(body).length;
    context.info.max_encrypted_request_bytes = String(limit);
    await expect(send()).rejects.toMatchObject({ code: "OperationUnavailable" });
    expect(fetch).toHaveBeenCalledTimes(2);
    context.info.max_encrypted_request_bytes = String(limit - 1);
    sign.mockClear();
    await expect(send()).rejects.toMatchObject({ code: "RequestTooLarge" });
    expect(sign).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});


afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

it("wipes the response key when request authorization fails", async () => {
  const { context, item, sign, fetch } = fixture();
  const responseKey = new Uint8Array(32).fill(7);
  vi.spyOn(p256.utils, "randomPrivateKey").mockReturnValueOnce(responseKey);
  sign.mockRejectedValueOnce(new Error("authorization refused"));
  await expect(executeOperationEnvelope(context, { type: "Decrypt", items: [item] })).rejects.toThrow("authorization refused");
  expect(responseKey).toEqual(new Uint8Array(32));
  expect(fetch).not.toHaveBeenCalled();
});

it("releases and wipes a request whose authorizer never answers, without sending it later", async () => {
  const { context, item, sign, fetch } = fixture();
  const responseKey = new Uint8Array(32).fill(7);
  vi.spyOn(p256.utils, "randomPrivateKey").mockReturnValueOnce(responseKey);
  let finish!: (signature: Uint8Array) => void;
  sign.mockImplementationOnce(() => new Promise<Uint8Array>((resolve) => { finish = resolve; }));
  const controller = new AbortController();
  const pending = executeOperationEnvelope(context, { type: "Decrypt", items: [item] }, undefined, controller.signal);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  await vi.waitFor(() => expect(sign).toHaveBeenCalled());
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(responseKey).toEqual(new Uint8Array(32));
  finish(new Uint8Array(64));
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(fetch).not.toHaveBeenCalled();
});

it("does not authorize or send an already cancelled request", async () => {
  const { context, item, sign, fetch } = fixture();
  await expect(executeOperationEnvelope(context, { type: "Decrypt", items: [item] }, undefined,
    AbortSignal.abort(new Error("cancelled")))).rejects.toThrow("cancelled");
  expect(sign).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});


it("times out a stalled operation transport and wipes its response key", async () => {
  vi.useFakeTimers();
  const { context, item, fetch } = fixture();
  const responseKey = new Uint8Array(32).fill(7);
  vi.spyOn(p256.utils, "randomPrivateKey").mockReturnValueOnce(responseKey);
  fetch.mockImplementationOnce(() => new Promise<Response>(() => {}));
  const pending = executeOperation({ ...context, requestTimeoutMs: 10 }, { type: "Decrypt", items: [item] });
  const rejected = expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
  await vi.advanceTimersByTimeAsync(10);
  await rejected;
  expect(fetch).toHaveBeenCalledOnce();
  expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  expect(responseKey).toEqual(new Uint8Array(32));
  expect(vi.getTimerCount()).toBe(0);
});


it("retains HTTP 429 and Retry-After without retrying or reading the rejected body", async () => {
  const { context, item, fetch } = fixture();
  const cancel = vi.fn();
  fetch.mockResolvedValueOnce(new Response(new ReadableStream({ cancel }), { status: 429, headers: { "retry-after": "3" } }));
  await expect(executeOperation(context, { type: "Decrypt", items: [item] })).rejects.toMatchObject({
    name: "TvcHttpError", code: "OperationRejected", status: 429, retryAfter: "3",
  });
  expect(fetch).toHaveBeenCalledOnce();
  expect(cancel).toHaveBeenCalledOnce();
});
