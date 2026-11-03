import { describe, expect, it, vi } from "vitest";
import type { HeliusPrivateWalletSession } from "helius-wallet-kit/core";
import { PrivateWalletConnection } from "./connection-store";

const session = (name: string) => ({ name }) as unknown as HeliusPrivateWalletSession;

/** An `open` the test resolves or rejects by hand, which records its signal. */
function controllableOpen() {
  let resolve!: (session: HeliusPrivateWalletSession) => void;
  let reject!: (error: unknown) => void;
  const signals: AbortSignal[] = [];
  const open = vi.fn((signal: AbortSignal) => {
    signals.push(signal);
    return new Promise<HeliusPrivateWalletSession>((res, rej) => {
      resolve = res;
      reject = rej;
    });
  });
  return { open, signals, resolve: (s: HeliusPrivateWalletSession) => resolve(s), reject: (e: unknown) => reject(e) };
}

function views(connection: PrivateWalletConnection) {
  const seen: string[] = [];
  connection.subscribe(() => seen.push(connection.snapshot().status));
  return seen;
}

describe("PrivateWalletConnection", () => {
  it("opens once and hands the same session to every caller", async () => {
    const connection = new PrivateWalletConnection();
    const seen = views(connection);
    const { open, resolve } = controllableOpen();
    const first = connection.connect(open);
    const second = connection.connect(open);
    expect(open).toHaveBeenCalledTimes(1);
    expect(connection.snapshot().status).toBe("connecting");
    resolve(session("a"));
    await expect(first).resolves.toBe(await second);
    expect(connection.snapshot()).toMatchObject({ status: "connected", session: session("a"), error: null });
    await expect(connection.connect(open)).resolves.toEqual(session("a"));
    expect(open).toHaveBeenCalledTimes(1);
    expect(seen).toEqual(["connecting", "connected"]);
  });

  it("reports a failed open and lets the next connect try again", async () => {
    const connection = new PrivateWalletConnection();
    const failing = vi.fn(() => Promise.reject(new Error("HeliusWalletSessionRequired")));
    await expect(connection.connect(failing)).rejects.toThrow("HeliusWalletSessionRequired");
    expect(connection.snapshot()).toMatchObject({ status: "error", session: null });
    expect(connection.snapshot().error?.message).toBe("HeliusWalletSessionRequired");
    const { open, resolve } = controllableOpen();
    const next = connection.connect(open);
    resolve(session("b"));
    await expect(next).resolves.toEqual(session("b"));
  });

  it("turns a synchronous throw inside open into a rejection", async () => {
    const connection = new PrivateWalletConnection();
    await expect(
      connection.connect(() => {
        throw new Error("PrivateWalletDevnetOnly");
      }),
    ).rejects.toThrow("PrivateWalletDevnetOnly");
    expect(connection.snapshot().status).toBe("error");
  });

  it("ends the session when the wallet binding changes, and ignores the late answer", async () => {
    const connection = new PrivateWalletConnection();
    connection.rebind("wallet-1");
    const { open, signals, resolve } = controllableOpen();
    const pending = connection.connect(open);
    connection.rebind("wallet-2");
    expect(signals[0]?.aborted).toBe(true);
    expect(connection.snapshot().status).toBe("idle");
    resolve(session("late"));
    await expect(pending).rejects.toThrow("PrivateWalletSessionExpired");
    expect(connection.snapshot()).toMatchObject({ status: "idle", session: null, error: null });
  });

  it("keeps the session across a rebind to the same wallet", async () => {
    const connection = new PrivateWalletConnection();
    connection.rebind("wallet-1");
    const { open, resolve } = controllableOpen();
    const pending = connection.connect(open);
    resolve(session("a"));
    await pending;
    connection.rebind("wallet-1");
    expect(connection.snapshot().status).toBe("connected");
  });

  it("disconnect aborts the session and returns to idle", async () => {
    const connection = new PrivateWalletConnection();
    const { open, signals, resolve } = controllableOpen();
    const pending = connection.connect(open);
    resolve(session("a"));
    await pending;
    connection.disconnect();
    expect(signals[0]?.aborted).toBe(true);
    expect(connection.snapshot()).toEqual({ status: "idle", session: null, error: null });
  });

  it("a caller's own signal cancels its connect without reporting an error", async () => {
    const connection = new PrivateWalletConnection();
    const { open, reject } = controllableOpen();
    const caller = new AbortController();
    const pending = connection.connect(open, { signal: caller.signal });
    caller.abort(new Error("UserLeft"));
    reject(caller.signal.reason);
    await expect(pending).rejects.toThrow("UserLeft");
    expect(connection.snapshot()).toEqual({ status: "idle", session: null, error: null });
    await expect(connection.connect(open, { signal: caller.signal })).rejects.toThrow("UserLeft");
  });
});
