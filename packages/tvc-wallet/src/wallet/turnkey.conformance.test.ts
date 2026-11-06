// Type-only: `@turnkey/core` is a dev dependency, never imported at run time.
import type { TurnkeyClient, TurnkeyClientMethods } from "@turnkey/core";
import { expect, it } from "vitest";

import { createTvcClient, type TvcClient } from "./client.js";

const endpoint = new URL("https://devnet.helius-rpc.com/v1/private-wallet");

// These compile only while Turnkey's client, and the `useTurnkey()` context
// of `@turnkey/react-wallet-kit` (its methods), fit `TvcTurnkey` as they are.
const fromClient = (turnkey: TurnkeyClient): TvcClient => createTvcClient({ network: "devnet", endpoint, turnkey });
const fromContext = (turnkey: TurnkeyClientMethods): TvcClient =>
  createTvcClient({ network: "devnet", endpoint, turnkey });

it("takes @turnkey/core's client and its methods as they are", () => {
  expect([fromClient, fromContext]).toHaveLength(2);
});
