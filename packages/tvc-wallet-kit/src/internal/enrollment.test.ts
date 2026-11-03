import { describe, expect, it } from "vitest";
import {
  isTvcEnrollmentMessage,
  TVC_ENROLLMENT_DOMAIN,
  TVC_ENROLLMENT_STATEMENT,
} from "helius-wallet-kit/core";
import {
  WALLET_ENROLLMENT_STATEMENT,
  walletEnrollmentMessage,
} from "@zolana/tvc-wallet/protocol";

const wallet = {
  organizationId: "user-sub-org",
  walletId: "wallet-id",
  address: "4E2agEUkMiuP3ABYbYTYXuU7bYyqPb3uGsLqs7RDd1U5",
};

// helius-wallet-kit signs an enrollment only when it matches its own copy of
// the format; tvc-wallet builds it. A drift would fail every connect.
describe("enrollment message", () => {
  it("is exactly what helius-wallet-kit agrees to sign", () => {
    expect(TVC_ENROLLMENT_STATEMENT).toBe(WALLET_ENROLLMENT_STATEMENT);
    const message = walletEnrollmentMessage({
      domain: TVC_ENROLLMENT_DOMAIN,
      organizationId: wallet.organizationId,
      turnkeyWalletId: wallet.walletId,
      solanaAddress: wallet.address,
      clientPublicKey: `04${"ab".repeat(64)}`,
      issuedAtMs: Date.now(),
    });
    expect(isTvcEnrollmentMessage(message, wallet)).toBe(true);
    expect(isTvcEnrollmentMessage(message, { ...wallet, walletId: "other" })).toBe(false);
  });
});
