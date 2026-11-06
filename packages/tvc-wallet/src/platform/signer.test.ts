import { describe, expect, it } from "vitest";
import { signedRequestMessage } from "./signer.js";
import { clientAuthMessage, requestDigest } from "../protocol/digest.js";
import type { SignTvcRequestInput } from "../client/operation-executor.js";
import type { OperationRequest, WalletDescriptor } from "../protocol/types.js";

const CLIENT_KEY_ID = "tvc-browser-p256-" + "11".repeat(16);
const WALLET_DESCRIPTOR = {
  version: 1,
  security_domain_id: "44".repeat(32),
  network: "devnet",
  turnkey_organization_id: "00000000-0000-0000-0000-00000000000b",
  turnkey_wallet_id: "wallet-1",
  address: "4".repeat(44),
  allowed_clients: [
    {
      client_public_key: `04${"55".repeat(64)}`,
      allowed_operations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"],
    },
  ],
  provisioning_signature: "66".repeat(64),
} satisfies WalletDescriptor;

function request(): OperationRequest {
  return {
    version: 1,
    request_id: "aa".repeat(32),
    issued_at_ms: "1750000000000",
    expires_at_ms: "1750000300000",
    target_release_id: "release-1",
    target_manifest_digest: "11".repeat(32),
    target_executable_digest: "22".repeat(32),
    quorum_key_id: "quorum-1",
    quorum_key_epoch: "1",
    wallet_descriptor: WALLET_DESCRIPTOR,
    sealed_seed: null,
    client_response_public_key: `04${"77".repeat(64)}`,
    operation: { type: "Bootstrap" },
    authorization: { client_key_id: CLIENT_KEY_ID, signature: "" },
  };
}

function input(overrides: Partial<SignTvcRequestInput> = {}): SignTvcRequestInput {
  const value = request();
  return {
    operation: value.operation,
    request: value,
    clientAuthDigest: new Uint8Array(32),
    clientAuthMessage: clientAuthMessage(requestDigest(value)),
    ...overrides,
  };
}

describe("request signer guard", () => {
  it("returns the message rederived from the request it was shown", () => {
    const value = input();
    expect(signedRequestMessage(value, CLIENT_KEY_ID)).toEqual(
      clientAuthMessage(requestDigest(value.request)),
    );
  });

  it("refuses to sign bytes that are not this request's authorization message", () => {
    // A signing oracle would sign whatever the caller handed it; the signer
    // must reject anything it cannot rederive from the disclosed request.
    expect(() =>
      signedRequestMessage(
        input({ clientAuthMessage: new Uint8Array(64).fill(9) }),
        CLIENT_KEY_ID,
      ),
    ).toThrowError(/OperationNotAllowed/);
    expect(() =>
      signedRequestMessage(input({ clientAuthMessage: new Uint8Array(0) }), CLIENT_KEY_ID),
    ).toThrowError(/OperationNotAllowed/);
  });

  it("refuses a message that belongs to a different request", () => {
    const other = request();
    other.operation = { type: "Derive", items: [] };
    expect(() =>
      signedRequestMessage(
        input({ clientAuthMessage: clientAuthMessage(requestDigest(other)) }),
        CLIENT_KEY_ID,
      ),
    ).toThrowError(/OperationNotAllowed/);
  });

  it("refuses a request authorized under another client key id", () => {
    expect(() => signedRequestMessage(input(), "tvc-browser-p256-" + "22".repeat(16))).toThrowError(
      /OperationNotAllowed/,
    );
  });
});
