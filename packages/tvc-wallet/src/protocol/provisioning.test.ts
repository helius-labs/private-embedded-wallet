import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";

import { verifyP256Prehash } from "../crypto/p256.js";
import { descriptorDigest } from "./digest.js";
import { decodeLowerHex, encodeLowerHex } from "./hex.js";
import { provisioningSecret, signWalletDescriptor } from "./provisioning.js";

const secret = new Uint8Array(32).fill(7);
const publicKey = encodeLowerHex(p256.getPublicKey(secret, false));
const releasePolicy = {
  securityDomainId: "2e".repeat(32),
  environment: "development" as const,
  allowedOperations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"] as const,
};
const input = {
  releasePolicy,
  turnkeyOrganizationId: "69FEBC39-7AC1-42C1-9786-F20F9CC52C5B",
  turnkeyWalletId: "wallet-1",
  address: "7oS2B9oQ6QwcyC6EmmxAoBYBoKnVCkpR5pqL3xC9wVYq",
  clientPublicKey: `04${"ab".repeat(64)}`,
};

describe("signWalletDescriptor", () => {
  it("writes the release's grant and signs the digest the enclave verifies", () => {
    const descriptor = signWalletDescriptor(input, secret);
    expect(descriptor).toMatchObject({
      version: 1,
      security_domain_id: releasePolicy.securityDomainId,
      environment: "development",
      turnkey_organization_id: "69febc39-7ac1-42c1-9786-f20f9cc52c5b",
      turnkey_wallet_id: "wallet-1",
      address: input.address,
      allowed_clients: [
        {
          client_public_key: input.clientPublicKey,
          allowed_operations: [...releasePolicy.allowedOperations],
        },
      ],
    });
    const signature = decodeLowerHex(descriptor.provisioning_signature);
    expect(signature).toHaveLength(64);
    expect(() =>
      verifyP256Prehash(decodeLowerHex(publicKey), descriptorDigest(descriptor), signature),
    ).not.toThrow();
  });

  it("refuses what the enclave would refuse", () => {
    const cases = [
      {
        ...input,
        releasePolicy: { ...releasePolicy, environment: "production" as const },
      },
      { ...input, turnkeyOrganizationId: "child-org" },
      { ...input, turnkeyWalletId: "" },
      { ...input, turnkeyWalletId: "w".repeat(129) },
      { ...input, address: "not-an-address" },
      { ...input, clientPublicKey: `02${"ab".repeat(32)}` },
    ];
    for (const invalid of cases) {
      expect(() => signWalletDescriptor(invalid, secret)).toThrow(/InvalidDescriptor/);
    }
  });
});

describe("provisioningSecret", () => {
  it("reads a Turnkey API key file and checks it is the expected key", () => {
    const json = JSON.stringify({
      private_key: `0x${encodeLowerHex(secret)}`,
      public_key: "",
    });
    expect(provisioningSecret(json, publicKey)).toEqual(secret);
    expect(() => provisioningSecret(json)).toThrow(/WrongProvisioningKey/);
    expect(() => provisioningSecret("{}", publicKey)).toThrow(/InvalidProvisioningKey/);
    expect(() => provisioningSecret("nope", publicKey)).toThrow(/InvalidProvisioningKey/);
  });
});
