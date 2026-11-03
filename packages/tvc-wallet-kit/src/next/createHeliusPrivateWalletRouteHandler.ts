import { PRIVATE_WALLET_DEPLOYMENT } from "../internal/deployment";
import { sameRequestOrigin } from "./internal/request-origin";
import { proxyZolanaGet, proxyZolanaPost } from "./internal/zolana-proxy";

const GATEWAY_ROUTES = new Set(["session", "enroll", "operations"]);
const GATEWAY_TIMEOUT_MS = 90_000;
const MAX_GATEWAY_BODY_BYTES = 512 * 1024;

type Context = { params: Promise<{ path: string[] }> };

function errorResponse(status = 502, error = "TvcProxyFailed"): Response {
  return Response.json(
    { error },
    { status, headers: { "cache-control": "no-store" } },
  );
}

function errorStatus(error: unknown): number {
  if (!(error instanceof Error)) return 502;
  if (error.message === "CrossOriginRequestDenied") return 403;
  if (error.message === "TvcRequestTooLarge") return 413;
  return 502;
}

async function requestBody(request: Request): Promise<ArrayBuffer> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > MAX_GATEWAY_BODY_BYTES) {
    throw new Error("TvcRequestTooLarge");
  }
  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_GATEWAY_BODY_BYTES) {
    throw new Error("TvcRequestTooLarge");
  }
  return body;
}

/**
 * Sends a private-wallet call to tvc-gateway with the server's Helius API key,
 * which the gateway resolves to the project each wallet's Turnkey sub-org is
 * named after.
 */
async function proxyGateway(route: string, request: Request): Promise<Response> {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) return errorResponse(503, "HeliusApiKeyRequired");
  const gatewayUrl = process.env.TVC_GATEWAY_URL ?? PRIVATE_WALLET_DEPLOYMENT.gatewayUrl;
  const upstream = new URL(`v1/private-wallet/${route}`, `${gatewayUrl}/`);
  const response = await fetch(upstream, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "x-api-key": apiKey,
    },
    body: await requestBody(request),
    signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
  });
  if (!response.ok) {
    const problem = await response.clone().text();
    console.error(`tvc-gateway ${route} ${String(response.status)}: ${problem.slice(0, 300)}`);
  }
  return new Response(response.body, {
    status: response.status,
    headers: {
      "content-type": response.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store",
    },
  });
}

/**
 * Mount at `app/api/tvc/[...path]/route.ts`. Serves the private wallet's
 * tvc-gateway calls (`POST session`, `enroll`, `operations`) and its Zolana
 * indexer and prover. Server env: `HELIUS_API_KEY`.
 */
export function createHeliusPrivateWalletRouteHandler(): {
  GET(request: Request, context: Context): Promise<Response>;
  POST(request: Request, context: Context): Promise<Response>;
} {
  return {
    async GET(request, context) {
      const { path } = await context.params;
      try {
        if (path[0] === "zolana") {
          return await proxyZolanaGet(path[1] ?? "", path.slice(2).join("/"), request);
        }
        return errorResponse(404);
      } catch {
        return errorResponse();
      }
    },
    async POST(request, context) {
      const { path } = await context.params;
      const route = path.join("/");
      try {
        sameRequestOrigin(request);
        if (GATEWAY_ROUTES.has(route)) {
          return await proxyGateway(route, request);
        }
        if (path[0] === "zolana") {
          return await proxyZolanaPost(
            path[1] ?? "",
            path.slice(2).join("/"),
            request,
          );
        }
        return errorResponse(404);
      } catch (error) {
        const code = error instanceof Error ? error.message : "TvcProxyFailed";
        console.error("Private wallet route failed", { route, code });
        return errorResponse(errorStatus(error));
      }
    },
  };
}
