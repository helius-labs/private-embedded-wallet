import { describe, expect, it } from "vitest";
import { compactLowS, signedRequestMessage } from "./signer.js";
import { clientAuthMessage, requestDigest } from "../protocol/digest.js";
import type { SignTvcRequestInput } from "../client/operation-executor.js";
import type { OperationRequest, WalletDescriptor } from "../protocol/types.js";

const CLIENT_KEY_ID = "spr-client-p256-" + "11".repeat(16);
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
  expires_at_ms: "1750086400000",
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

  it("returns the client-auth text: the domain and the request digest in hex", () => {
    const value = input();
    expect(signedRequestMessage(value, CLIENT_KEY_ID)).toMatch(/^spr-tvc-client-auth-v1:[0-9a-f]{64}$/);
  });

  it("refuses to sign text that is not this request's authorization message", () => {
    // A signing oracle would sign whatever the caller handed it; the signer
    // must reject anything it cannot rederive from the disclosed request.
    const message = clientAuthMessage(requestDigest(request()));
    for (const other of ["", "anything", message.toUpperCase(), `${message}\n`, message.replace(":", "\u0000")]) {
      expect(() => signedRequestMessage(input({ clientAuthMessage: other }), CLIENT_KEY_ID)).toThrowError(
        /OperationNotAllowed/,
      );
    }
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
    expect(() => signedRequestMessage(input(), "spr-client-p256-" + "22".repeat(16))).toThrowError(
      /OperationNotAllowed/,
    );
  });
});

describe("compactLowS", () => {
  it("keeps a low-S signature and flips a high-S one", () => {
    const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    const r = new Uint8Array(32).fill(1);
    const low = Uint8Array.from([...r, ...new Uint8Array(31), 5]);
    expect(compactLowS(low)).toEqual(low);
    const highS = (order - 5n).toString(16).padStart(64, "0");
    const high = Uint8Array.from([...r, ...highS.match(/../g)!.map((byte) => Number.parseInt(byte, 16))]);
    expect(compactLowS(high)).toEqual(low);
    expect(() => compactLowS(new Uint8Array(70))).toThrowError(/InvalidSignatureEncoding/);
  });
});
