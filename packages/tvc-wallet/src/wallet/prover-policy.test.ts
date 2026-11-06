import { afterEach, describe, expect, it, vi } from "vitest";

import type { TvcTransport } from "../client/transport.js";
import { PROVER_POLICY_URLS, TvcProverPolicy, attestationReuseMs } from "./prover-policy.js";
import { POLICY_URL, policyFile } from "./prover-policy.testkit.js";

const NOW_MS = 1_800_000_000_000;
const NOW_SECS = NOW_MS / 1_000;

/** Answers each download with the next of `answers`, the last one repeating. */
function served(...answers: (() => Response)[]) {
  const urls: URL[] = [];
  const transport: TvcTransport = {
    fetch: vi.fn(async (url: URL) => {
      urls.push(url);
      return (answers.length > 1 ? answers.shift() : answers[0])!();
    }),
  };
  return { transport, urls };
}

const file = (options: Parameters<typeof policyFile>[0]) => () => Response.json(policyFile(options));

describe("TvcProverPolicy", () => {
  afterEach(() => vi.restoreAllMocks());

  it("downloads the file the SDK pins for each network", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const { transport, urls } = served(file({ expiresAt: NOW_SECS + 3_600 }));
    for (const network of ["devnet", "mainnet"] as const) {
      await TvcProverPolicy.forNetwork(network, transport).current();
    }
    expect(urls.map(String)).toEqual([PROVER_POLICY_URLS.devnet, PROVER_POLICY_URLS.mainnet]);
    expect(() => TvcProverPolicy.forNetwork("testnet" as "devnet")).toThrowError(/UnknownNetwork/);
  });

  it("holds the file for its max age and downloads it again after", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const { transport, urls } = served(
      file({ expiresAt: NOW_SECS + 3_600 }),
      file({ version: 2, expiresAt: NOW_SECS + 7_200 }),
    );
    const policy = new TvcProverPolicy(POLICY_URL, transport);
    const first = await policy.current();
    expect(first).toMatchObject({ version: 1, maxAgeSecs: 600, expiresAt: NOW_SECS + 3_600 });
    expect(first.file).toEqual(policyFile({ expiresAt: NOW_SECS + 3_600 }));
    now.mockReturnValue(NOW_MS + 599_000);
    expect(await policy.current()).toBe(first);
    now.mockReturnValue(NOW_MS + 600_000);
    expect(await policy.current()).toMatchObject({ version: 2 });
    policy.invalidate();
    await policy.current();
    expect(urls).toHaveLength(3);
  });

  it("keeps an unexpired file while downloads fail, and not past its expiry", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const { transport } = served(
      file({ expiresAt: NOW_SECS + 900 }),
      () => new Response("down", { status: 503 }),
    );
    const policy = new TvcProverPolicy(POLICY_URL, transport);
    const held = await policy.current();
    now.mockReturnValue(NOW_MS + 600_000);
    expect((await policy.current()).file).toBe(held.file);
    now.mockReturnValue(NOW_MS + 900_000);
    await expect(policy.current()).rejects.toMatchObject({ code: "ProverPolicyUnavailable", status: 503 });
  });

  it("takes whatever the publisher serves next, older or not", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const { transport } = served(
      file({ version: 2, expiresAt: NOW_SECS + 3_600 }),
      file({ version: 1, expiresAt: NOW_SECS + 7_200 }),
    );
    const policy = new TvcProverPolicy(POLICY_URL, transport);
    expect(await policy.current()).toMatchObject({ version: 2 });
    policy.invalidate();
    expect(await policy.current()).toMatchObject({ version: 1 });
  });

  it("shares one download, ends only the cancelled caller's wait and stops once nobody waits", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    let release!: () => void;
    const signals: AbortSignal[] = [];
    const transport: TvcTransport = {
      fetch: vi.fn(async (_url: URL, init?: RequestInit) => {
        signals.push(init!.signal!);
        await new Promise<void>((done) => (release = done));
        init!.signal!.throwIfAborted();
        return Response.json(policyFile({ expiresAt: NOW_SECS + 3_600 }));
      }),
    };
    const policy = new TvcProverPolicy(POLICY_URL, transport);
    const first = new AbortController();
    const cancelled = policy.current(first.signal);
    const waiting = policy.current();
    const rejected = expect(cancelled).rejects.toThrow("first left");
    await vi.waitFor(() => expect(signals).toHaveLength(1));
    first.abort(new Error("first left"));
    await rejected;
    expect(signals[0]!.aborted).toBe(false);
    release();
    await expect(waiting).resolves.toMatchObject({ version: 1 });
    expect(transport.fetch).toHaveBeenCalledOnce();

    policy.invalidate();
    const alone = new AbortController();
    const abandoned = policy.current(alone.signal);
    const left = expect(abandoned).rejects.toThrow("left");
    await vi.waitFor(() => expect(signals).toHaveLength(2));
    alone.abort(new Error("left"));
    await left;
    expect(signals[1]!.aborted).toBe(true);
    release();
    // The abandoned download leaves the held file to be downloaded again.
    const next = policy.current();
    await vi.waitFor(() => expect(signals).toHaveLength(3));
    release();
    await expect(next).resolves.toMatchObject({ version: 1 });
  });

  it("refuses a malformed or expired file", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const hex = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("hex");
    const good = policyFile({ expiresAt: NOW_SECS + 60 });
    const part = (value: unknown) => ({ payload: hex(value), signatures: [] });
    const fresh = part({ issued_at: NOW_SECS - 60, expires_at: NOW_SECS + 60 });
    for (const body of [
      [],
      { payload: good.release.payload, signatures: [] },
      { release: good.release },
      { ...good, extra: 1 },
      { release: { payload: "7B7D", signatures: [] }, freshness: good.freshness },
      { release: part({ version: 1, expires_at: NOW_SECS + 60, policy: {} }), freshness: fresh },
      { release: part({ version: 0, expires_at: NOW_SECS + 60, policy: { max_age_secs: 600 } }), freshness: fresh },
      { release: good.release, freshness: part({ issued_at: NOW_SECS + 60, expires_at: NOW_SECS + 60 }) },
      { release: good.release, freshness: { ...good.freshness, extra: 1 } },
    ]) {
      const { transport } = served(() => Response.json(body));
      await expect(new TvcProverPolicy(POLICY_URL, transport).current(), JSON.stringify(body)).rejects.toMatchObject({
        code: "ProverPolicyInvalid",
      });
    }
    for (const expired of [file({ expiresAt: NOW_SECS }), file({ expiresAt: NOW_SECS + 3_600, freshUntil: NOW_SECS })]) {
      const { transport } = served(expired);
      await expect(new TvcProverPolicy(POLICY_URL, transport).current()).rejects.toMatchObject({
        code: "ProverPolicyExpired",
      });
    }
  });

  it("stays in force until the earlier of the release and freshness expiries", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const { transport } = served(file({ expiresAt: NOW_SECS + 7_200, freshUntil: NOW_SECS + 900 }));
    expect(await new TvcProverPolicy(POLICY_URL, transport).current()).toMatchObject({
      version: 1,
      issuedAt: NOW_SECS + 900 - 3_600,
      expiresAt: NOW_SECS + 900,
    });
  });

  it("lets one attestation serve for the max age and never past the expiry", () => {
    const held = (maxAgeSecs: number, expiresAt: number) => ({
      file: policyFile({ expiresAt }),
      version: 1,
      maxAgeSecs,
      issuedAt: 0,
      expiresAt,
      fetchedAtMs: 0,
    });
    expect(attestationReuseMs(held(600, 10_000), 0)).toBe(600_000);
    expect(attestationReuseMs(held(600, 1), 0)).toBe(1_000);
    expect(attestationReuseMs(held(600, 1), 2_000)).toBe(0);
  });
});
