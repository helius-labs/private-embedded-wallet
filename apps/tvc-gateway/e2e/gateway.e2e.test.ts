import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { getAddressDecoder } from "@solana/kit";
import {
  identityOf,
  sealedSeedOf,
  type TvcClient,
  type TvcTransport,
  type VerifiedConnection,
} from "@heliuslabs/spr-embedded-wallet";
import {
  decodeLowerHex,
  encodeLowerHex,
  walletEnrollmentMessage,
  type BootstrapResult,
  type WalletDescriptor,
} from "@heliuslabs/spr-embedded-wallet/protocol";
import { createLocalTvcClient } from "@heliuslabs/spr-embedded-wallet/testing";
import { beforeAll, describe, expect, inject, it } from "vitest";
import {
  ORGANIZATION_ID,
  PROJECT_ID,
  TURNKEY_WALLET_ID,
  testkit,
} from "./fixtures.js";

const { gatewayUrl, originAuth, apiKey, walletSeedHex } = inject("stack");
const privateWallet = `${gatewayUrl}/v1/private-wallet`;
const ownerSeed = decodeLowerHex(walletSeedHex);
const ownerAddress = getAddressDecoder().decode(ed25519.getPublicKey(ownerSeed));
const clientPublicKey = encodeLowerHex(
  p256.getPublicKey(decodeLowerHex(testkit.clientPrivateKeyHex), false),
);

/** The headers gatekeeper adds to every request it forwards. */
function gatekeeperHeaders(project = PROJECT_ID) {
  return {
    authorization: originAuth,
    "x-helius-project-id": project,
    "content-type": "application/json",
  };
}

async function post(path: string, body: unknown, project?: string) {
  const response = await fetch(`${privateWallet}${path}`, {
    method: "POST",
    headers: gatekeeperHeaders(project),
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return { status: response.status, headers: response.headers, body: await response.json() };
}

/** An RFC 9457 problem with the gateway's `code`. */
function problem(status: number, code: string) {
  return { status, body: expect.objectContaining({ status, code }) };
}

/** A `POST /enroll` body the owner signed for the gateway at `domain`. */
function enrollment({ issuedAtMs = Date.now(), signer = ownerSeed, domain = new URL(gatewayUrl).host } = {}) {
  const fields = {
    organizationId: ORGANIZATION_ID,
    turnkeyWalletId: TURNKEY_WALLET_ID,
    solanaAddress: ownerAddress,
    clientPublicKey,
    issuedAtMs,
  };
  const message = new TextEncoder().encode(walletEnrollmentMessage({ domain, ...fields }));
  return { ...fields, ownerSignature: encodeLowerHex(ed25519.sign(message, signer)) };
}

it("serves health without credentials", async () => {
  expect((await fetch(`${gatewayUrl}/health`)).status).toBe(200);
});

it("serves only /session, /enroll and /operations", async () => {
  for (const path of ["/info", "/ping", "/policy", "/wallet-grant", "/enrollment-challenge"]) {
    expect(await post(path, {}), path).toMatchObject(problem(404, "NotFound"));
  }
});

describe("enrollment", () => {
  it("answers a failure as an RFC 9457 problem", async () => {
    const response = await fetch(`${privateWallet}/enroll`, {
      method: "POST",
      headers: gatekeeperHeaders(),
      body: JSON.stringify(enrollment({ issuedAtMs: Date.now() - 6 * 60_000 })),
    });
    expect(response.headers.get("content-type")).toBe("application/problem+json");
    expect(await response.json()).toEqual({
      title: "Bad Request",
      status: 400,
      detail: "the enrollment is more than five minutes old or more than 30 seconds ahead",
      code: "StaleEnrollment",
    });
  });

  it("refuses an enrollment older than five minutes", async () => {
    expect(await post("/enroll", enrollment({ issuedAtMs: Date.now() - 6 * 60_000 }))).toMatchObject(
      problem(400, "StaleEnrollment"),
    );
  });

  it("refuses an enrollment another key signed", async () => {
    const intruder = ed25519.utils.randomPrivateKey();
    expect(await post("/enroll", enrollment({ signer: intruder }))).toMatchObject(
      problem(400, "InvalidOwnerEnrollmentSignature"),
    );
  });

  it("refuses an enrollment signed for another domain", async () => {
    expect(await post("/enroll", enrollment({ domain: "wallet.example" }))).toMatchObject(
      problem(400, "InvalidOwnerEnrollmentSignature"),
    );
  });

  it("refuses an enrollment for another project's sub-organization", async () => {
    expect(await post("/enroll", enrollment(), "other-project")).toMatchObject(
      problem(403, "SubOrganizationNotOwned"),
    );
  });

  it("answers the same descriptor for the same enrollment", async () => {
    const signed = enrollment();
    const first = await post("/enroll", signed);
    expect(first.status).toBe(200);
    expect(first.body.descriptor).toMatchObject({
      address: ownerAddress,
      allowed_clients: [{ client_public_key: clientPublicKey }],
    });
    expect((await post("/enroll", signed)).body).toEqual(first.body);
  });
});

describe("a wallet enrolled through the gateway", () => {
  const sent: { path: string; body: string; answer: string }[] = [];
  const transport: TvcTransport = {
    async fetch(url, init) {
      const response = await fetch(url, { ...init, headers: gatekeeperHeaders() });
      sent.push({ path: url.pathname, body: String(init?.body ?? ""), answer: await response.clone().text() });
      return response;
    },
  };
  let descriptor: WalletDescriptor;
  let tvc: TvcClient;
  let connection: VerifiedConnection;
  let bootstrap: BootstrapResult;
  const firstSent = () => {
    const operation = sent.find(({ path }) => path.endsWith("/operations"));
    if (!operation) throw new Error("no operation was sent");
    return operation;
  };
  const firstOperation = () =>
    JSON.parse(firstSent().body) as { descriptor: WalletDescriptor; request: { ciphertext: string } };

  beforeAll(async () => {
    descriptor = (await post("/enroll", enrollment())).body.descriptor;
    tvc = createLocalTvcClient({
      backend: { kind: "gateway", endpoint: new URL(privateWallet) },
      solanaAddress: ownerAddress,
      walletDescriptor: descriptor,
      transport,
    });
    connection = await tvc.connectAndVerify();
    bootstrap = await tvc.bootstrap(connection);
  });

  it("connects with one /session request", () => {
    expect(sent.filter(({ path }) => !path.endsWith("/operations")).map(({ path }) => path)).toEqual([
      "/v1/private-wallet/session",
    ]);
  });

  it("bootstraps through /operations with a grant the gateway adds", () => {
    expect(identityOf(bootstrap).solanaAddress).toBe(ownerAddress);
    expect(firstOperation().request).not.toHaveProperty("wallet_grant");
  });

  it("answers TransactionKeys for the bootstrapped wallet", async () => {
    const identity = identityOf(bootstrap);
    const keys = await tvc.transactionKeys(connection, sealedSeedOf(bootstrap), [
      { viewing_public_key: identity.shieldedViewingPublicKey, first_nullifier: "01".padStart(64, "0") },
    ]);
    expect(keys).toHaveLength(1);
  });

  it("answers a resent operation with the first answer", async () => {
    const resent = await post("/operations", firstOperation());
    expect(resent.status).toBe(200);
    expect(resent.headers.get("idempotent-replayed")).toBe("true");
    expect(resent.body).toEqual(JSON.parse(firstSent().answer));
  });

  it("refuses another project's resend of an answered operation", async () => {
    expect(await post("/operations", firstOperation(), "other-project")).toMatchObject(
      problem(409, "ReplayedRequest"),
    );
  });

  it("refuses an operation on another project's wallet", async () => {
    const fresh = firstOperation();
    fresh.request.ciphertext = "abcd";
    expect(await post("/operations", fresh, "other-project")).toMatchObject(
      problem(403, "SubOrganizationNotOwned"),
    );
  });

  it("refuses a descriptor this gateway did not provision, or none", async () => {
    const tampered = firstOperation();
    tampered.descriptor.turnkey_wallet_id = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
    expect(await post("/operations", tampered)).toMatchObject(problem(403, "InvalidDescriptor"));
    expect(await post("/operations", firstOperation().request)).toMatchObject(
      problem(400, "InvalidJson"),
    );
  });
});

describe("a direct caller with a Helius API key", () => {
  async function postDirect(path: string, body: unknown, headers: Record<string, string> = {}) {
    const response = await fetch(`${privateWallet}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }

  it("is refused without a key, or with one Helius does not know", async () => {
    expect(await postDirect("/session", {})).toMatchObject(problem(401, "ApiKeyRequired"));
    expect(await postDirect(`/session?api-key=${crypto.randomUUID()}`, {})).toMatchObject(
      problem(401, "ApiKeyInvalid"),
    );
  });

  it("enrolls with the key in X-Api-Key", async () => {
    const enrolled = await postDirect("/enroll", enrollment(), { "x-api-key": apiKey });
    expect(enrolled.status).toBe(200);
    expect(enrolled.body.descriptor.turnkey_organization_id).toBe(ORGANIZATION_ID);
  });

  it("connects and bootstraps with the key in the endpoint's query", async () => {
    const { descriptor } = (await postDirect("/enroll", enrollment(), { "x-api-key": apiKey })).body;
    const tvc = createLocalTvcClient({
      backend: { kind: "gateway", endpoint: new URL(`${privateWallet}?api-key=${apiKey}`) },
      solanaAddress: ownerAddress,
      walletDescriptor: descriptor,
    });
    const connection = await tvc.connectAndVerify();
    expect(identityOf(await tvc.bootstrap(connection)).solanaAddress).toBe(ownerAddress);
  });
});
