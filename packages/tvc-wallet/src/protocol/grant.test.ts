import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";
import { DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY, walletGrantSecret } from "./grant.js";
import { encodeLowerHex } from "./hex.js";

const secret = new Uint8Array(32).fill(9);

describe("walletGrantSecret", () => {
  it("reads a key file and refuses a key the enclave was not built with", () => {
    const publicKey = encodeLowerHex(p256.getPublicKey(secret, false));
    const json = JSON.stringify({ private_key: encodeLowerHex(secret) });
    expect(walletGrantSecret(json, publicKey)).toEqual(secret);
    expect(DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY).not.toBe(publicKey);
    expect(() => walletGrantSecret(json)).toThrow(/WrongWalletGrantKey/);
    expect(() => walletGrantSecret("{}", publicKey)).toThrow(/InvalidWalletGrantKey/);
    expect(() => walletGrantSecret("nope", publicKey)).toThrow(/InvalidWalletGrantKey/);
  });
});
