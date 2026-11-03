import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHeliusPrivateWalletRouteHandler } from "./createHeliusPrivateWalletRouteHandler";

const ORIGIN = "https://wallet.example.com";
const GATEWAY = "https://gateway.example";

function context(...path: string[]) {
  return { params: Promise.resolve({ path }) };
}

function post(
  path: string,
  body: string,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ORIGIN}/api/tvc/${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      host: "wallet.example.com",
      origin: ORIGIN,
      ...headers,
    },
    body,
  });
}

describe("createHeliusPrivateWalletRouteHandler", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.stubEnv("TVC_GATEWAY_URL", GATEWAY);
    vi.stubEnv("HELIUS_API_KEY", "server-key");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("rejects a cross-origin POST before routing it", async () => {
    const { POST } = createHeliusPrivateWalletRouteHandler();
    const response = await POST(
      post("session", "{}", { origin: "https://evil.example" }),
      context("session"),
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "TvcProxyFailed" });
  });

  it("forwards a gateway call with the server's API key and nothing else of its own", async () => {
    const fetch = vi.fn(async () =>
      Response.json({ descriptor: { version: 1 } }, { status: 200 }),
    );
    vi.stubGlobal("fetch", fetch);
    const { POST } = createHeliusPrivateWalletRouteHandler();
    const response = await POST(post("enroll", '{"issuedAtMs":1}'), context("enroll"));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({ descriptor: { version: 1 } });
    const [url, init] = fetch.mock.calls[0] as unknown as [URL, RequestInit];
    expect(String(url)).toBe(`${GATEWAY}/v1/private-wallet/enroll`);
    expect(init.headers).toEqual({
      accept: "application/json",
      "content-type": "application/json",
      "x-api-key": "server-key",
    });
    expect(new TextDecoder().decode(init.body as ArrayBuffer)).toBe('{"issuedAtMs":1}');
  });

  it("polls a proof's status on its proving key's path with only the job id", async () => {
    vi.stubEnv("ZOLANA_PROVER_URL", "https://prover.example");
    const fetch = vi.fn(async () => Response.json({ status: "running" }, { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const { GET } = createHeliusPrivateWalletRouteHandler();
    const status = (path: string, query: string) =>
      GET(
        new Request(`${ORIGIN}/api/tvc/zolana/prover/${path}?${query}`),
        context("zolana", "prover", ...path.split("/")),
      );

    const response = await status("prove/merge_8_1/status", "jobId=job-1&extra=1");
    expect(response.status).toBe(200);
    const [url] = fetch.mock.calls[0] as unknown as [URL];
    expect(String(url)).toBe("https://prover.example/prove/merge_8_1/status?jobId=job-1");

    expect((await status("prove/merge_8_1/status", "jobId=../x")).status).toBe(502);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("reaches devnet-e's indexer and prover directly, without the server's API key", async () => {
    vi.stubEnv("HELIUS_API_KEY", "");
    const fetch = vi.fn(async () => Response.json({ result: {} }, { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const { GET, POST } = createHeliusPrivateWalletRouteHandler();

    await POST(
      post("zolana/indexer/getMerkleProofs", "{}"),
      context("zolana", "indexer", "getMerkleProofs"),
    );
    await POST(
      post("zolana/prover/prove/merge_8_1", "{}"),
      context("zolana", "prover", "prove", "merge_8_1"),
    );
    await GET(
      new Request(`${ORIGIN}/api/tvc/zolana/prover/prove/merge_8_1/status?jobId=job-1`),
      context("zolana", "prover", "prove", "merge_8_1", "status"),
    );

    const urls = fetch.mock.calls.map((call) => String((call as unknown as [URL])[0]));
    expect(urls).toEqual([
      "https://d34xe1hqb2ibg2.cloudfront.net/getMerkleProofs",
      "https://dd73hh473h6ha.cloudfront.net/prove/merge_8_1",
      "https://dd73hh473h6ha.cloudfront.net/prove/merge_8_1/status?jobId=job-1",
    ]);
  });

  it("reaches gatekeeper's zolana routes with the server's API key", async () => {
    vi.stubEnv("ZOLANA_INDEXER_URL", "https://beta-devnet.helius-rpc.com/v1/spr");
    vi.stubEnv("ZOLANA_PROVER_URL", "https://beta-devnet.helius-rpc.com/v1/spr");
    const fetch = vi.fn(async () => Response.json({ result: {} }, { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const { GET, POST } = createHeliusPrivateWalletRouteHandler();

    await POST(
      post("zolana/indexer/getMerkleProofs", "{}"),
      context("zolana", "indexer", "getMerkleProofs"),
    );
    await POST(
      post("zolana/prover/prove/merge_8_1", "{}"),
      context("zolana", "prover", "prove", "merge_8_1"),
    );
    await GET(
      new Request(`${ORIGIN}/api/tvc/zolana/prover/prove/merge_8_1/status?jobId=job-1`),
      context("zolana", "prover", "prove", "merge_8_1", "status"),
    );

    const urls = fetch.mock.calls.map((call) => String((call as unknown as [URL])[0]));
    expect(urls).toEqual([
      "https://beta-devnet.helius-rpc.com/v1/spr/getMerkleProofs?api-key=server-key",
      "https://beta-devnet.helius-rpc.com/v1/spr/prove/merge_8_1?api-key=server-key",
      "https://beta-devnet.helius-rpc.com/v1/spr/prove/merge_8_1/status?api-key=server-key&jobId=job-1",
    ]);

    const keyless = await POST(
      post("zolana/prover/prove", "{}"),
      context("zolana", "prover", "prove"),
    );
    expect(keyless.status).toBe(404);
    expect(fetch).toHaveBeenCalledTimes(3);

    vi.stubEnv("HELIUS_API_KEY", "");
    const refused = await POST(
      post("zolana/indexer/getMerkleProofs", "{}"),
      context("zolana", "indexer", "getMerkleProofs"),
    );
    expect(refused.status).toBe(503);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("forwards a sealed proof untouched to the configured prover", async () => {
    const answer = new Uint8Array([9, 8, 7]);
    const fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(answer, {
          status: 200,
          headers: { "content-type": "application/octet-stream", "spr-tee": "v1" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    const { POST } = createHeliusPrivateWalletRouteHandler();
    const enc = "ab".repeat(32);
    const sealed = (route: string, headers: Record<string, string>) =>
      new Request(`${ORIGIN}/api/tvc/zolana/prover/${route}`, {
        method: "POST",
        headers: {
          host: "wallet.example.com",
          origin: ORIGIN,
          "content-type": "application/octet-stream",
          ...headers,
        },
        body: new Uint8Array([1, 2, 3]),
      });

    const response = await POST(
      sealed("prove/merge_8_1", { "spr-tee": "v1", "spr-tee-enc": enc }),
      context("zolana", "prover", "prove", "merge_8_1"),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("spr-tee")).toBe("v1");
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(answer);
    const [url, init] = fetch.mock.calls[0] as unknown as [URL, RequestInit];
    expect(String(url)).toBe("https://dd73hh473h6ha.cloudfront.net/prove/merge_8_1");
    const headers = new Headers(init.headers);
    expect(headers.get("spr-tee")).toBe("v1");
    expect(headers.get("spr-tee-enc")).toBe(enc);
    expect(new Uint8Array(init.body as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));

    for (const [route, headers] of [
      ["prove/merge_8_1", { "spr-tee": "v2", "spr-tee-enc": enc }],
      ["prove/merge_8_1", { "spr-tee": "v1", "spr-tee-enc": "ab" }],
      ["prove/merge_8_1/indexed", { "spr-tee": "v1", "spr-tee-enc": enc }],
      ["prove", { "spr-tee": "v1", "spr-tee-enc": enc }],
    ] as const) {
      const refused = await POST(
        sealed(route, headers),
        context("zolana", "prover", ...route.split("/")),
      );
      expect(refused.status, route).toBe(400);
    }

    // The seal binds the route, so a prover override on another path opens it too.
    vi.stubEnv("ZOLANA_PROVER_URL", "https://prover.example");
    const moved = await POST(
      sealed("prove/merge_8_1", { "spr-tee": "v1", "spr-tee-enc": enc }),
      context("zolana", "prover", "prove", "merge_8_1"),
    );
    expect(moved.status).toBe(200);
    expect(String(fetch.mock.calls[1]?.[0])).toBe("https://prover.example/prove/merge_8_1");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("passes the prover's attestation for a client nonce through", async () => {
    const fetch = vi.fn(async () => Response.json({ platform: "aws-nitro" }, { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const { GET } = createHeliusPrivateWalletRouteHandler();
    const attest = (query: string) =>
      GET(
        new Request(`${ORIGIN}/api/tvc/zolana/prover/attestation?${query}`),
        context("zolana", "prover", "attestation"),
      );

    const nonce = "42".repeat(32);
    const response = await attest(`nonce=${nonce}&api-key=client-key`);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ platform: "aws-nitro" });
    expect(String((fetch.mock.calls[0] as unknown as [URL])[0])).toBe(
      `https://dd73hh473h6ha.cloudfront.net/attestation?nonce=${nonce}`,
    );
    expect((await attest("nonce=42")).status).toBe(400);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("passes a gateway refusal through", async () => {
    const problem = { title: "Bad Request", status: 400, detail: "stale", code: "StaleEnrollment" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(problem, {
          status: 400,
          headers: { "content-type": "application/problem+json" },
        }),
      ),
    );
    const { POST } = createHeliusPrivateWalletRouteHandler();
    const response = await POST(post("enroll", "{}"), context("enroll"));

    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toBe("application/problem+json");
    await expect(response.json()).resolves.toEqual(problem);
  });

  it("refuses without the server's API key", async () => {
    vi.stubEnv("HELIUS_API_KEY", "");
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const { POST } = createHeliusPrivateWalletRouteHandler();
    const response = await POST(post("session", "{}"), context("session"));

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "HeliusApiKeyRequired" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("serves no enclave or provisioning route of its own", async () => {
    const { POST } = createHeliusPrivateWalletRouteHandler();
    for (const path of [["v1", "ping"], ["boot-proof"], ["wallet-grant"], ["enrollment-challenge"]]) {
      const response = await POST(post(path.join("/"), "{}"), context(...path));
      expect(response.status, path.join("/")).toBe(404);
    }
  });

  it("rejects an oversized request without reading its body", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const { POST } = createHeliusPrivateWalletRouteHandler();
    const response = await POST(
      post("operations", "{}", { "content-length": String(512 * 1024 + 1) }),
      context("operations"),
    );

    expect(response.status).toBe(413);
    expect(fetch).not.toHaveBeenCalled();
  });
});
