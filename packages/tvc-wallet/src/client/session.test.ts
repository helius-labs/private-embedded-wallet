import { afterEach, expect, it, vi } from "vitest";
import { createVerifiedConnection, type ConnectedTvcRuntime } from "./connection.js";
import { sessionFromConnector } from "./session.js";
import type { OperationsConfig } from "./operation-executor.js";

const operations: OperationsConfig = {
  walletDescriptor: { version: 1, environment: "development", security_domain_id: "00".repeat(32),
    turnkey_organization_id: "org", turnkey_wallet_id: "wallet", address: "11111111111111111111111111111111", allowed_clients: [], provisioning_signature: "" },
  authorizer: { clientKeyId: "client", authorizeTvcRequest: async () => new Uint8Array() },
};
function runtime(label: string): ConnectedTvcRuntime {
  return {
    connection: createVerifiedConnection(label), backend: { kind: "enclave", endpoint: new URL("https://tvc.example") },
    info: { version: 1, environment: "development", security_domain_id: "00".repeat(32), release_id: label,
      manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32), quorum_public_key: "", quorum_key_id: "quorum", quorum_key_epoch: "1",
      ephemeral_public_key: "", supported_operations: [], max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144", proof_type: "", boot_proof_lookup_key: "" },
    transport: { fetch: vi.fn() }, releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 999999n, nowMs: () => 1n,
    trustVerifier: { verifyOperationAppProof: vi.fn(), verifyCustodyProofs: vi.fn() },
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
afterEach(() => vi.useRealTimers());

it("lets one caller cancel while another receives the shared verified connection", async () => {
  const connection = runtime("shared");
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect, operations);
  const controller = new AbortController();
  const first = session.connectAndVerify({ signal: controller.signal });
  const second = session.connectAndVerify();
  const rejected = expect(first).rejects.toThrow("cancelled");
  await Promise.resolve();
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(connect).toHaveBeenCalledOnce();
  expect(connect.mock.calls[0]![0].aborted).toBe(false);
  ready.resolve(connection);
  await expect(second).resolves.toBe(connection.connection);
  expect(session.requireOperationContext(connection.connection).operations).toBe(operations);
});

it("aborts an abandoned connection and refuses its late result after a replacement verifies", async () => {
  const old = runtime("old");
  const current = runtime("current");
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise).mockResolvedValueOnce(current);
  const session = sessionFromConnector(connect, operations);
  // Establish an initial connection, then start a connector that ignores cancellation.
  await session.connectAndVerify();
  const controller = new AbortController();
  const pending = session.connectAndVerify({ signal: controller.signal });
  const rejected = expect(pending).rejects.toThrow("cancelled");
  await Promise.resolve();
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(connect.mock.calls[1]![0].aborted).toBe(true);
  connect.mockResolvedValueOnce(current);
  await expect(session.connectAndVerify()).resolves.toBe(current.connection);
  ready.resolve(old);
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(session.requireOperationContext(current.connection).operations).toBe(operations);
  expect(() => session.requireOperationContext(old.connection)).toThrow("OperationNotConfigured");
});

it("bounds a stalled verification by default and releases its flight", async () => {
  vi.useFakeTimers();
  const connect = vi.fn((_signal: AbortSignal) => new Promise<ConnectedTvcRuntime>(() => {}));
  const session = sessionFromConnector(connect, operations);
  const pending = session.connectAndVerify();
  const rejected = expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
  await vi.advanceTimersByTimeAsync(120_000);
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(true);
  connect.mockResolvedValueOnce(runtime("next"));
  await expect(session.connectAndVerify()).resolves.toMatchObject({ releaseId: "next" });
  expect(vi.getTimerCount()).toBe(0);
});

it("uses the configured default verification deadline", async () => {
  vi.useFakeTimers();
  const connect = vi.fn((_signal: AbortSignal) => new Promise<ConnectedTvcRuntime>(() => {}));
  const session = sessionFromConnector(connect, operations, 25);
  const pending = session.connectAndVerify();
  const rejected = expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
  await vi.advanceTimersByTimeAsync(25);
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});

it("keeps another caller alive when a shorter deadline expires", async () => {
  vi.useFakeTimers();
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect, operations);
  const short = session.connectAndVerify({ timeoutMs: 10 });
  const long = session.connectAndVerify({ timeoutMs: 100 });
  const rejected = expect(short).rejects.toMatchObject({ name: "TimeoutError" });
  await vi.advanceTimersByTimeAsync(10);
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(false);
  ready.resolve(runtime("shared"));
  await expect(long).resolves.toMatchObject({ releaseId: "shared" });
  expect(vi.getTimerCount()).toBe(0);
});

it("does not connect for an aborted caller or invalid timeout", async () => {
  const connect = vi.fn(async () => runtime("unused"));
  const session = sessionFromConnector(connect, operations);
  await expect(session.connectAndVerify({ signal: AbortSignal.abort(new Error("cancelled")) })).rejects.toThrow("cancelled");
  for (const timeoutMs of [0, -1, NaN, Infinity, 0.5, 2_147_483_648]) {
    await expect(session.connectAndVerify({ timeoutMs })).rejects.toThrow("InvalidRequestTimeout");
  }
  expect(connect).not.toHaveBeenCalled();
});
