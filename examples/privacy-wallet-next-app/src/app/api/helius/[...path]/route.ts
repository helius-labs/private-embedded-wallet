// Catch-all for the Helius server-side routes the wallet kit uses (RPC, send,
// transaction history, plan). Mainnet keeps the library's Helius routing. The
// demo's devnet chain traffic uses the configured Solana RPC so a stale Helius
// project key cannot break local shield/transfer/unshield testing.
//
// The factory resolves the API key in this order:
//   1. `x-helius-api-key` request header (what the hook sends)
//   2. process.env.HELIUS_API_KEY (server-only, production path)
//   3. process.env.NEXT_PUBLIC_HELIUS_API_KEY (browser-configured demo key)
//
// Routing sends through here enables Helius Sender's optimized landing. This
// route is optional: without it, the SDK talks to Helius directly from the
// browser using key-less Secure RPC URLs. See the WaaS quickstart docs.

import { NextResponse } from "next/server";
import { createHeliusRouteHandler } from "helius-wallet-kit/next";
import { sameRequestOrigin } from "../../tvc/request-origin";

const helius = createHeliusRouteHandler();
const DEFAULT_DEVNET_RPC = "https://api.devnet.solana.com";

type Context = { params: Promise<{ path: string[] }> };

function errorResponse(status = 502, error = "DevnetRpcFailed") {
  return NextResponse.json({ error }, { status });
}

async function forwardDevnetRpc(request: Request): Promise<Response> {
  sameRequestOrigin(request);
  const response = await fetch(
    process.env.DEVNET_SOLANA_RPC_URL ?? DEFAULT_DEVNET_RPC,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: await request.arrayBuffer(),
      cache: "no-store",
      redirect: "error",
    },
  );
  return new Response(response.body, {
    status: response.status,
    headers: {
      "content-type":
        response.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store",
    },
  });
}

async function sendDevnetTransaction(request: Request): Promise<Response> {
  sameRequestOrigin(request);
  const { transaction } = (await request.json()) as {
    transaction?: unknown;
  };
  if (typeof transaction !== "string" || transaction.length === 0) {
    return errorResponse(400, "transaction is required");
  }

  const response = await fetch(
    process.env.DEVNET_SOLANA_RPC_URL ?? DEFAULT_DEVNET_RPC,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "wallet-demo",
        method: "sendTransaction",
        params: [
          transaction,
          { encoding: "base64", skipPreflight: false, maxRetries: 3 },
        ],
      }),
      cache: "no-store",
      redirect: "error",
    },
  );
  if (!response.ok) return errorResponse();

  const body = (await response.json()) as {
    result?: unknown;
    error?: { message?: unknown };
  };
  if (body.error) {
    return errorResponse(
      400,
      typeof body.error.message === "string"
        ? body.error.message
        : "DevnetRpcRejected",
    );
  }
  if (typeof body.result !== "string") {
    return errorResponse(502, "DevnetRpcRejected");
  }
  return NextResponse.json({ signature: body.result });
}

export const GET = helius.GET;

export async function POST(request: Request, context: Context) {
  const { path } = await context.params;
  const route = path.join("/");
  try {
    if (
      route === "rpc" &&
      (new URL(request.url).searchParams.get("cluster") ?? "devnet") ===
        "devnet"
    ) {
      return await forwardDevnetRpc(request);
    }
    if (route === "send") {
      const body = (await request.clone().json()) as { cluster?: unknown };
      if (body.cluster !== "mainnet-beta") {
        return await sendDevnetTransaction(request);
      }
    }
    return await helius.POST(request, context);
  } catch (error) {
    return errorResponse(
      error instanceof Error && error.message === "CrossOriginRequestDenied"
        ? 403
        : 502,
      error instanceof Error ? error.message : "DevnetRpcFailed",
    );
  }
}
