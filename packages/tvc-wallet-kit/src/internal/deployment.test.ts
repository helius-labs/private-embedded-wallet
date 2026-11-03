import { describe, expect, it } from "vitest";
import { PRIVATE_WALLET_DEPLOYMENT } from "./deployment";

describe("private wallet deployment", () => {
  it("uses TLS for every package-owned service endpoint", () => {
    for (const endpoint of [
      PRIVATE_WALLET_DEPLOYMENT.gatewayUrl,
      PRIVATE_WALLET_DEPLOYMENT.indexerUrl,
      PRIVATE_WALLET_DEPLOYMENT.proverUrl,
    ]) {
      expect(new URL(endpoint).protocol).toBe("https:");
    }
  });
});
