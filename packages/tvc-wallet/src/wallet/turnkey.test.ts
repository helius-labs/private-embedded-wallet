import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { SignTvcRequestInput } from "../client/operation-executor.js";
import type { TvcTransport } from "../client/transport.js";
import { clientAuthMessage, clientKeyIdFor, requestDigest } from "../protocol/digest.js";
import { walletEnrollmentMessage } from "../protocol/enrollment.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { OperationRequest, WalletDescriptor } from "../protocol/types.js";
import { turnkeyClientKeys, type TvcTurnkey, type TvcTurnkeySession } from "./turnkey.js";

const ORGANIZATION_ID = "00000000-0000-4000-8000-00000000000a";
const WALLET_ID = "00000000-0000-4000-8000-00000000000b";
const ENDPOINT = new URL("https://devnet.helius-rpc.com/v1/private-wallet?api-key=key");
const NOW_MS = 1_800_000_000_000n;
const P256_ORDER = p256.CURVE.n;
const te = new TextEncoder();

type Enrollment = {
  organizationId: string;
  turnkeyWalletId: string;
  solanaAddress: string;
  clientPublicKey: string;
  issuedAtMs: number;
  ownerSignature: string;
};

/** A Turnkey client with one logged-in session and one embedded Solana wallet. */
function fakeTurnkey() {
  const owner = ed25519.utils.randomPrivateKey();
  const ownerPublic = ed25519.getPublicKey(owner);
  const address = getAddressDecoder().decode(ownerPublic);
  const sessionKeys = new Map<string, Uint8Array>();
  const login = () => {
    const secret = p256.utils.randomPrivateKey();
    const publicKey = encodeLowerHex(p256.getPublicKey(secret, true));
    sessionKeys.set(publicKey, secret);
    session = { organizationId: ORGANIZATION_ID, publicKey };
    return publicKey;
  };
  let session: TvcTurnkeySession | undefined;
  const account = { address, addressFormat: "ADDRESS_FORMAT_SOLANA", source: "embedded" };
  const turnkey = {
    getSession: vi.fn(async () => session),
    // The browser's WebCrypto answers either half of S; the client normalizes.
    signWithApiKey: vi.fn(async ({ message, publicKey }: { message: string; publicKey: string }) => {
      const signature = p256.sign(sha256(te.encode(message)), sessionKeys.get(publicKey)!, { lowS: true });
      return encodeLowerHex(
        Uint8Array.from([
          ...p256.CURVE.Fp.toBytes(signature.r),
          ...p256.CURVE.Fp.toBytes(P256_ORDER - signature.s),
        ]),
      );
    }),
    fetchWallets: vi.fn(async () => [
      {
        walletId: "connected-wallet",
        accounts: [{ ...account, address: "11111111111111111111111111111111", source: "connected" }],
      },
      {
        walletId: WALLET_ID,
        accounts: [{ ...account, address: "0xabc", addressFormat: "ADDRESS_FORMAT_ETHEREUM" }, account],
      },
    ]),
    signMessage: vi.fn(async ({ message }: { message: string }) => {
      const signature = ed25519.sign(te.encode(message), owner);
      return { r: encodeLowerHex(signature.slice(0, 32)), s: encodeLowerHex(signature.slice(32)), v: "00" };
    }),
  } satisfies TvcTurnkey;
  return { turnkey, address, account, ownerPublic, login, logout: () => { session = undefined; } };
}

/** A gateway that answers each enrollment with a descriptor for its key. */
function fakeGateway(answer: (enrollment: Enrollment) => Response | undefined = () => undefined) {
  const enrollments: { url: URL; body: Enrollment }[] = [];
  const fetch = vi.fn(async (url: URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as Enrollment;
    enrollments.push({ url, body });
    const descriptor: WalletDescriptor = {
      version: 1,
      security_domain_id: "11".repeat(32),
      network: "devnet",
      turnkey_organization_id: body.organizationId,
      turnkey_wallet_id: body.turnkeyWalletId,
      address: body.solanaAddress,
      allowed_clients: [
        {
          client_public_key: body.clientPublicKey,
          allowed_operations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"],
        },
      ],
      provisioning_signature: "22".repeat(64),
    };
    return answer(body) ?? new Response(JSON.stringify({ descriptor }), { status: 200 });
  });
  return { transport: { fetch }, enrollments };
}

function keysOf(turnkey: TvcTurnkey, transport: TvcTransport, solanaAddress?: string) {
  return turnkeyClientKeys({
    turnkey,
    network: "devnet",
    endpoint: ENDPOINT,
    transport,
    nowMs: () => NOW_MS,
    ...(solanaAddress === undefined ? {} : { solanaAddress }),
  });
}

describe("the Turnkey session key", () => {
  it("is enrolled once, by the wallet owner, for the gateway's host and network", async () => {
    const { turnkey, address, account, ownerPublic, login } = fakeTurnkey();
    const sessionKey = login();
    const gateway = fakeGateway();
    const keys = keysOf(turnkey, gateway.transport);

    const key = await keys.current();
    expect(key.id).toBe(sessionKey);
    const [first, second] = await Promise.all([key.operations(), key.operations()]);
    expect(second).toBe(first);
    expect(await (await keys.current()).operations()).toBe(first);
    expect(gateway.enrollments).toHaveLength(1);

    const [{ url, body }] = gateway.enrollments as [{ url: URL; body: Enrollment }];
    expect(url.href).toBe("https://devnet.helius-rpc.com/v1/private-wallet/enroll?api-key=key");
    const clientPublicKey = encodeLowerHex(p256.ProjectivePoint.fromHex(sessionKey).toRawBytes(false));
    expect(body).toEqual({
      organizationId: ORGANIZATION_ID,
      turnkeyWalletId: WALLET_ID,
      solanaAddress: address,
      clientPublicKey,
      issuedAtMs: Number(NOW_MS),
      ownerSignature: expect.stringMatching(/^[0-9a-f]{128}$/),
    });
    const message = walletEnrollmentMessage({ domain: ENDPOINT.host, network: "devnet", ...body });
    expect(turnkey.signMessage).toHaveBeenCalledWith({
      message,
      walletAccount: account,
      encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
      hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
    });
    expect(ed25519.verify(decodeLowerHex(body.ownerSignature), te.encode(message), ownerPublic)).toBe(true);
    expect(first.descriptor.allowed_clients[0]?.client_public_key).toBe(clientPublicKey);
    expect(first.signer.clientKeyId).toBe(clientKeyIdFor(decodeLowerHex(clientPublicKey)));
  });

  it("signs the client-auth text with signWithApiKey, normalized to low S", async () => {
    const { turnkey, login } = fakeTurnkey();
    const sessionKey = login();
    const { descriptor, signer } = await (await keysOf(turnkey, fakeGateway().transport).current()).operations();
    const request = {
      version: 1,
      request_id: "aa".repeat(32),
      issued_at_ms: "1800000000000",
      expires_at_ms: "1800000300000",
      target_release_id: "release",
      target_manifest_digest: "11".repeat(32),
      target_executable_digest: "22".repeat(32),
      quorum_key_id: "quorum",
      quorum_key_epoch: "1",
      wallet_descriptor: descriptor,
      sealed_seed: null,
      client_response_public_key: `04${"77".repeat(64)}`,
      operation: { type: "Bootstrap" },
      authorization: { client_key_id: signer.clientKeyId, signature: "" },
    } satisfies OperationRequest;
    const message = clientAuthMessage(requestDigest(request));
    const input: SignTvcRequestInput = {
      operation: request.operation,
      request,
      clientAuthDigest: sha256(te.encode(message)),
      clientAuthMessage: message,
    };
    const signature = await signer.signRequest(input);
    expect(turnkey.signWithApiKey).toHaveBeenCalledWith({ message, publicKey: sessionKey });
    const publicKey = decodeLowerHex(descriptor.allowed_clients[0]!.client_public_key);
    expect(p256.verify(signature, sha256(te.encode(message)), publicKey, { lowS: true })).toBe(true);
    await expect(signer.signRequest({ ...input, clientAuthMessage: `${message}0` })).rejects.toMatchObject({
      code: "OperationNotAllowed",
    });
  });

  it("is enrolled again after a new login, and kept for a session it has seen", async () => {
    const { turnkey, login, logout } = fakeTurnkey();
    const gateway = fakeGateway();
    const keys = keysOf(turnkey, gateway.transport);
    login();
    const first = await keys.current();
    await first.operations();
    login();
    const second = await keys.current();
    expect(second.id).not.toBe(first.id);
    const enrolled = await second.operations();
    expect(gateway.enrollments.map(({ body }) => body.clientPublicKey)).toEqual([
      expect.any(String),
      enrolled.descriptor.allowed_clients[0]?.client_public_key,
    ]);
    expect(await keys.current()).toBe(second);

    logout();
    await expect(keys.current()).rejects.toMatchObject({ code: "TurnkeySessionRequired" });
  });

  it("finds the organization's one embedded Solana account, or the one named", async () => {
    const { turnkey, address, login } = fakeTurnkey();
    login();
    const named = await (await keysOf(turnkey, fakeGateway().transport, address).current()).operations();
    expect(named.descriptor.address).toBe(address);

    const missing = keysOf(turnkey, fakeGateway().transport, "11111111111111111111111111111111");
    await expect((await missing.current()).operations()).rejects.toMatchObject({ code: "WalletAccountNotFound" });

    const [, wallet] = await turnkey.fetchWallets();
    turnkey.fetchWallets.mockResolvedValueOnce([
      wallet!,
      { walletId: "second", accounts: [{ ...wallet!.accounts[1]!, address: "So11111111111111111111111111111111111111112" }] },
    ]);
    const several = keysOf(turnkey, fakeGateway().transport);
    await expect((await several.current()).operations()).rejects.toMatchObject({ code: "WalletAccountAmbiguous" });

    turnkey.fetchWallets.mockResolvedValueOnce([]);
    const none = keysOf(turnkey, fakeGateway().transport);
    await expect((await none.current()).operations()).rejects.toMatchObject({ code: "WalletAccountNotFound" });
  });

  it("refuses a refused enrollment or another key's descriptor, and enrolls again next time", async () => {
    const { turnkey, login } = fakeTurnkey();
    login();
    let answer: Response | undefined = new Response("{}", { status: 403 });
    const gateway = fakeGateway(() => answer);
    const key = await keysOf(turnkey, gateway.transport).current();
    await expect(key.operations()).rejects.toMatchObject({ code: "EnrollmentRejected", status: 403 });

    const other = encodeLowerHex(p256.getPublicKey(p256.utils.randomPrivateKey(), false));
    answer = undefined;
    gateway.transport.fetch.mockImplementationOnce(async (_url: URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Enrollment;
      return new Response(JSON.stringify({
        descriptor: {
          version: 1,
          security_domain_id: "11".repeat(32),
          network: "devnet",
          turnkey_organization_id: body.organizationId,
          turnkey_wallet_id: body.turnkeyWalletId,
          address: body.solanaAddress,
          allowed_clients: [{ client_public_key: other, allowed_operations: ["Decrypt"] }],
          provisioning_signature: "22".repeat(64),
        },
      }));
    });
    await expect(key.operations()).rejects.toMatchObject({ code: "InvalidDescriptor" });

    await expect(key.operations()).resolves.toMatchObject({ descriptor: { network: "devnet" } });
    expect(gateway.transport.fetch).toHaveBeenCalledTimes(3);
  });
});
