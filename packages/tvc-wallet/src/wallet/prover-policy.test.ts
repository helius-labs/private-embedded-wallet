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
    expect(() => TvcProverPolicy.forNetwork("testnet" as "devnet")).toThrowError("UnknownProverNetwork");
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

  it("refuses an older version or another payload under the same version", async () => {
    for (const next of [
      file({ version: 1, expiresAt: NOW_SECS + 7_200 }),
      file({ version: 1, maxAgeSecs: 300, expiresAt: NOW_SECS + 3_600 }),
    ]) {
      vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
      const { transport } = served(file({ version: 1, expiresAt: NOW_SECS + 3_600 }), next);
      const policy = new TvcProverPolicy(POLICY_URL, transport);
      await policy.current();
      policy.invalidate();
      await expect(policy.current()).rejects.toMatchObject({ code: "ProverPolicyRollback" });
    }
  });

  it("refuses a malformed or expired file", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW_MS);
    const hex = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("hex");
    for (const body of [
      [],
      { payload: "7b7d" },
      { payload: "7B7D", signatures: [] },
      { payload: hex({ version: 1, expires_at: NOW_SECS + 60, policy: {} }), signatures: [] },
      { payload: hex({ version: 0, expires_at: NOW_SECS + 60, policy: { max_age_secs: 600 } }), signatures: [] },
      { ...policyFile({ expiresAt: NOW_SECS + 60 }), extra: 1 },
    ]) {
      const { transport } = served(() => Response.json(body));
      await expect(new TvcProverPolicy(POLICY_URL, transport).current(), JSON.stringify(body)).rejects.toMatchObject({
        code: "ProverPolicyInvalid",
      });
    }
    const { transport } = served(file({ expiresAt: NOW_SECS }));
    await expect(new TvcProverPolicy(POLICY_URL, transport).current()).rejects.toMatchObject({
      code: "ProverPolicyExpired",
    });
  });

  it("lets one attestation serve for the max age and never past the expiry", () => {
    const held = (maxAgeSecs: number, expiresAt: number) => ({
      file: policyFile({ expiresAt }),
      version: 1,
      maxAgeSecs,
      expiresAt,
      fetchedAtMs: 0,
    });
    expect(attestationReuseMs(held(600, 10_000), 0)).toBe(600_000);
    expect(attestationReuseMs(held(600, 1), 0)).toBe(1_000);
    expect(attestationReuseMs(held(600, 1), 2_000)).toBe(0);
  });
});
