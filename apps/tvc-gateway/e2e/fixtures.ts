import testkit from "../../../packages/tvc-wallet/src/local-testkit.json" with { type: "json" };

export { testkit };

/** The project gatekeeper names in `X-Helius-Project-Id`; the mock Turnkey names every sub-org after it. */
export const PROJECT_ID = "local-e2e-project";
export const ORGANIZATION_ID = "1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b";
export const TURNKEY_WALLET_ID = "2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d";
