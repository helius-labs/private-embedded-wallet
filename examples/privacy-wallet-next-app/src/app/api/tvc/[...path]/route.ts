import { createHeliusPrivateWalletRouteHandler } from "@zolana/tvc-wallet-kit/next";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export const { GET, POST } = createHeliusPrivateWalletRouteHandler();
