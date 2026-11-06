import { afterEach, expect, it, vi } from "vitest";
import type { ConnectedTvcRuntime } from "./connection.js";
import { sessionFromConnector } from "./session.js";
function runtime(label: string, nowMs: () => bigint = () => 1n): ConnectedTvcRuntime {
  return {
    backend: { kind: "enclave", endpoint: new URL("https://tvc.example") },
    info: { version: 1, network: "devnet", security_domain_id: "00".repeat(32), release_id: label,
      manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32), quorum_public_key: "", quorum_key_id: "quorum", quorum_key_epoch: "1",
      ephemeral_public_key: "", supported_operations: [], max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144", proof_type: "" },
    transport: { fetch: vi.fn() }, releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 999999n, nowMs,
    trustVerifier: { verifyOperationAppProof: vi.fn() },
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
afterEach(() => vi.useRealTimers());

it("verifies once on first use and holds the connection", async () => {
  const connect = vi.fn(async (_signal: AbortSignal) => runtime("held"));
  const session = sessionFromConnector(connect);
  const first = await session.context();
  expect(first).toMatchObject({ info: { release_id: "held" } });
  await expect(session.context()).resolves.toBe(first);
  expect(connect).toHaveBeenCalledOnce();
});

it("verifies again once the release policy's window no longer holds, and after forget", async () => {
  let now = 1n;
  const connect = vi.fn(async (_signal: AbortSignal) => runtime(`at-${now}`, () => now));
  const session = sessionFromConnector(connect);
  const first = await session.context();
  now = 1_000_000n;
  connect.mockRejectedValueOnce(new Error("ExpiredRequest"));
  await expect(session.context()).rejects.toThrow("ExpiredRequest");
  expect(connect).toHaveBeenCalledTimes(2);
  now = 2n;
  const second = await session.context();
  expect(second).not.toBe(first);
  expect(connect).toHaveBeenCalledTimes(3);

  session.forget(first);
  await expect(session.context()).resolves.toBe(second);
  session.forget(second);
  const third = await session.context();
  expect(third).not.toBe(second);
  expect(connect).toHaveBeenCalledTimes(4);
});

it("verifies anew after reset, and a verification in flight at the reset never becomes current", async () => {
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect);
  const inFlight = session.context();
  await Promise.resolve();
  session.reset();
  connect.mockResolvedValueOnce(runtime("after"));
  const after = await session.context();
  expect(after.info.release_id).toBe("after");
  ready.resolve(runtime("before"));
  await expect(inFlight).resolves.toMatchObject({ info: { release_id: "before" } });
  await expect(session.context()).resolves.toBe(after);

  session.reset();
  connect.mockResolvedValueOnce(runtime("again"));
  await expect(session.context()).resolves.toMatchObject({ info: { release_id: "again" } });
  expect(connect).toHaveBeenCalledTimes(3);
});

it("lets one caller cancel while another receives the shared verification", async () => {
  const connection = runtime("shared");
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect);
  const controller = new AbortController();
  const first = session.context({ signal: controller.signal });
  const second = session.context();
  const rejected = expect(first).rejects.toThrow("cancelled");
  await Promise.resolve();
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(connect).toHaveBeenCalledOnce();
  expect(connect.mock.calls[0]![0].aborted).toBe(false);
  ready.resolve(connection);
  await expect(second).resolves.toMatchObject({ info: { release_id: "shared" } });
});

it("aborts an abandoned verification and refuses its late result after a replacement verifies", async () => {
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect);
  // Start a connector that ignores cancellation, then abandon it.
  const controller = new AbortController();
  const pending = session.context({ signal: controller.signal });
  const rejected = expect(pending).rejects.toThrow("cancelled");
  await Promise.resolve();
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(true);
  connect.mockResolvedValueOnce(runtime("current"));
  const current = await session.context();
  expect(current.info.release_id).toBe("current");
  ready.resolve(runtime("old"));
  await new Promise((resolve) => setTimeout(resolve, 0));
  await expect(session.context()).resolves.toBe(current);
  expect(connect).toHaveBeenCalledTimes(2);
});

it("bounds a stalled verification by default and releases its flight", async () => {
  vi.useFakeTimers();
  const connect = vi.fn((_signal: AbortSignal) => new Promise<ConnectedTvcRuntime>(() => {}));
  const session = sessionFromConnector(connect);
  const pending = session.context();
  const rejected = expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
  await vi.advanceTimersByTimeAsync(120_000);
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(true);
  connect.mockResolvedValueOnce(runtime("next"));
  await expect(session.context()).resolves.toMatchObject({ info: { release_id: "next" } });
  expect(vi.getTimerCount()).toBe(0);
});

it("uses the configured default verification deadline", async () => {
  vi.useFakeTimers();
  const connect = vi.fn((_signal: AbortSignal) => new Promise<ConnectedTvcRuntime>(() => {}));
  const session = sessionFromConnector(connect, 25);
  const pending = session.context();
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
  const session = sessionFromConnector(connect);
  const short = session.context({ timeoutMs: 10 });
  const long = session.context({ timeoutMs: 100 });
  const rejected = expect(short).rejects.toMatchObject({ name: "TimeoutError" });
  await vi.advanceTimersByTimeAsync(10);
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(false);
  ready.resolve(runtime("shared"));
  await expect(long).resolves.toMatchObject({ info: { release_id: "shared" } });
  expect(vi.getTimerCount()).toBe(0);
});

it("does not connect for an aborted caller or invalid timeout", async () => {
  const connect = vi.fn(async () => runtime("unused"));
  const session = sessionFromConnector(connect);
  await expect(session.context({ signal: AbortSignal.abort(new Error("cancelled")) })).rejects.toThrow("cancelled");
  for (const timeoutMs of [0, -1, NaN, Infinity, 0.5, 2_147_483_648]) {
    await expect(session.context({ timeoutMs })).rejects.toThrow("InvalidRequestTimeout");
  }
  expect(connect).not.toHaveBeenCalled();
});
