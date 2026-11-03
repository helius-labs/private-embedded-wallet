import { createRequire } from "node:module";
import { expect, it } from "vitest";

it("uses the same Turnkey context for the Helius provider and private connector", () => {
  const demo = createRequire(import.meta.url);
  const walletKit = createRequire(demo.resolve("helius-wallet-kit/package.json"));
  // Different peer dependency resolutions create different React contexts even
  // at the same Turnkey SDK version, leaving the approval hook without a session.
  expect(demo.resolve("@turnkey/react-wallet-kit")).toBe(walletKit.resolve("@turnkey/react-wallet-kit"));
  expect(demo.resolve("react")).toBe(walletKit.resolve("react"));
});
