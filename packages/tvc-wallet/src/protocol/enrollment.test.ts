import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { walletEnrollmentMessage, type WalletEnrollment } from "./enrollment.js";

const vector = JSON.parse(readFileSync(new URL(
  "../../../../apps/tvc-gateway/fixtures/wallet-enrollment.json", import.meta.url,
), "utf8")) as { enrollment: WalletEnrollment; message: string };
const { enrollment } = vector;

describe("walletEnrollmentMessage", () => {
  it("matches the message tvc-gateway verifies", () => {
    expect(walletEnrollmentMessage(enrollment)).toBe(vector.message);
  });

  it("names the gateway's network as the chain", () => {
    expect(walletEnrollmentMessage(enrollment)).toContain("\nChain ID: devnet\n");
    expect(walletEnrollmentMessage({ ...enrollment, network: "mainnet" })).toContain(
      "\nChain ID: mainnet\n",
    );
  });

  it("changes with every field", () => {
    const message = walletEnrollmentMessage(enrollment);
    for (const changed of [
      { ...enrollment, domain: "wallet.example" },
      { ...enrollment, network: "mainnet" as const },
      { ...enrollment, organizationId: "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e" },
      { ...enrollment, clientPublicKey: `04${"cd".repeat(64)}` },
      { ...enrollment, issuedAtMs: enrollment.issuedAtMs + 1 },
    ]) {
      expect(walletEnrollmentMessage(changed)).not.toBe(message);
    }
  });

  it("refuses a malformed time or a field that would add a line", () => {
    for (const issuedAtMs of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2, 253_402_300_799_999]) {
      expect(() => walletEnrollmentMessage({ ...enrollment, issuedAtMs })).toThrow(/InvalidDecimal/);
    }
    for (const organizationId of [`${enrollment.organizationId}\n`, `${enrollment.organizationId}\r`]) {
      expect(() => walletEnrollmentMessage({ ...enrollment, organizationId })).toThrow(/InvalidDescriptor/);
    }
    expect(() => walletEnrollmentMessage({ ...enrollment, network: "devnet\n" as "devnet" })).toThrow(
      /UnknownNetwork/,
    );
  });
});
