import { beforeEach, describe, expect, it, vi } from "vitest";
import { createTvcClient, TvcProverPolicy } from "@zolana/tvc-wallet";
import {
  walletEnrollmentMessage,
  type WalletDescriptor,
  type WalletEnrollment,
} from "@zolana/tvc-wallet/protocol";
import type { HeliusWalletSession } from "helius-wallet-kit/core";
import { TVC_ENROLLMENT_DOMAIN } from "helius-wallet-kit/core";
import {
  PRIVATE_WALLET_RELEASE_POLICY,
  PRIVATE_WALLET_SERVICE_PUBLIC_KEY,
} from "./release";
import { openPrivateWallet } from "./connect";

const test = vi.hoisted(() => ({
  events: [] as string[],
  prover: undefined as unknown,
  loadState: vi.fn(),
  saveState: vi.fn(),
  loadIdentity: vi.fn(),
  saveIdentity: vi.fn(),
  clearState: vi.fn(),
  createZolana: vi.fn(),
  signedEnrollments: [] as string[],
  enrollBodies: [] as Record<string, unknown>[],
}));

vi.mock("./state", () => ({
  loadPrivateWalletState: test.loadState,
  savePrivateWalletState: test.saveState,
  loadKnownIdentity: test.loadIdentity,
  saveKnownIdentity: test.saveIdentity,
  clearPrivateWalletState: test.clearState,
}));

vi.mock("./zolana", () => ({
  createPrivateZolanaClient: test.createZolana,
}));

vi.mock("./revocable-keys", () => ({
  revocableWalletKeys: (keys: unknown) => keys,
}));

const authorizer = {
  clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
  clientPublicKey: `04${"11".repeat(64)}`,
  authorizer: {},
};
vi.mock("@zolana/tvc-wallet/browser", () => ({
  loadOrCreatePersistentBrowserTvcAuthorizer: async () => authorizer,
}));

const identity = {
  solanaAddress: "7oS2B9oQ6QwcyC6EmmxAoBYBoKnVCkpR5pqL3xC9wVYq",
  shieldedOwnerHash: "22".repeat(32),
  shieldedNullifierPublicKey: "33".repeat(32),
  shieldedViewingPublicKey: `03${"44".repeat(32)}`,
};
const walletKeys = { address: vi.fn() };

vi.mock("@zolana/tvc-wallet", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@zolana/tvc-wallet")>()),
  createTvcClient: vi.fn((config: { operations?: unknown }) => ({
    connectAndVerify: async () => {
      test.events.push(config.operations ? "verify:operations" : "verify:deployment");
      return { releaseId: PRIVATE_WALLET_RELEASE_POLICY.policy.releaseId };
    },
    bootstrap: async () => {
      test.events.push("bootstrap");
      return {
        solana_address: identity.solanaAddress,
        shielded_owner_hash: identity.shieldedOwnerHash,
        shielded_nullifier_public_key: identity.shieldedNullifierPublicKey,
        shielded_viewing_public_key: identity.shieldedViewingPublicKey,
        sealed_seed: "55".repeat(64),
      };
    },
  })),
  identityOf: () => identity,
  sealedSeedOf: () => ({ sealedSeed: "55".repeat(64) }),
  TvcKeys: class {
    address = walletKeys.address;
    constructor(input: { prover: unknown }) {
      test.prover = input.prover;
    }
  },
}));

const descriptor: WalletDescriptor = {
  version: 1,
  security_domain_id: PRIVATE_WALLET_RELEASE_POLICY.policy.securityDomainId,
  environment: "development",
  turnkey_organization_id: "11111111-2222-4333-8444-555555555555",
  turnkey_wallet_id: "22222222-3333-4444-8555-666666666666",
  address: identity.solanaAddress,
  allowed_clients: [
    {
      client_public_key: authorizer.clientPublicKey,
      allowed_operations: [
        ...PRIVATE_WALLET_RELEASE_POLICY.policy.allowedOperations,
      ],
    },
  ],
  provisioning_signature: "66".repeat(64),
};

const wallet = {
  organizationId: "11111111-2222-4333-8444-555555555555",
  walletId: "22222222-3333-4444-8555-666666666666",
  walletName: "Solana Wallet",
  walletAccountId: "33333333-4444-4555-8666-777777777777",
  address: identity.solanaAddress,
};
const authority = {
  serviceUserId: "55555555-6666-4777-8888-999999999999",
  apiKeyId: "66666666-7777-4888-8999-aaaaaaaaaaaa",
};

function walletSession(): HeliusWalletSession {
  return {
    status: "authenticated",
    userId: "44444444-5555-4666-8777-888888888888",
    parentOrganizationId: "9b98a0d8-04a4-47a3-9dc3-afa84c686de4",
    organizationId: wallet.organizationId,
    activeWallet: wallet,
    authorizeTvcWallet: vi.fn(async () => {
      test.events.push("authorize");
      return authority;
    }),
    signTvcEnrollment: vi.fn(async (message: string) => {
      test.events.push("enrollment:owner-signature");
      test.signedEnrollments.push(message);
      return "77".repeat(64);
    }),
  } as unknown as HeliusWalletSession;
}

function open() {
  return openPrivateWallet({
    origin: "https://wallet.example.com",
    solanaRpcUrl: "https://wallet.example.com/api/helius/rpc?cluster=devnet",
    walletSession: walletSession(),
    wallet,
    signal: new AbortController().signal,
    withBootstrapApproval: async (_owner, start, signal) => {
      test.events.push("owner-approval");
      return start(signal);
    },
  });
}

const storedState = () => ({
  version: 7,
  clientKeyId: authorizer.clientKeyId,
  walletDescriptor: descriptor,
  identity,
  sealedSeed: { sealedSeed: "55".repeat(64) },
  registered: false,
  turnkeyServicePublicKey: PRIVATE_WALLET_SERVICE_PUBLIC_KEY,
  tvcAuthority: authority,
});

describe("openPrivateWallet", () => {
  beforeEach(() => {
    vi.mocked(createTvcClient).mockClear();
    test.events.length = 0;
    test.signedEnrollments.length = 0;
    test.enrollBodies.length = 0;
    test.loadState.mockReset().mockResolvedValue(null);
    test.saveState.mockReset().mockImplementation(async () => {
      test.events.push("persist");
    });
    test.loadIdentity.mockReset().mockResolvedValue(null);
    test.saveIdentity.mockReset().mockResolvedValue(undefined);
    test.clearState.mockReset().mockResolvedValue(undefined);
    test.createZolana.mockReset().mockResolvedValue({ kind: "zolana" });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        if (url === "https://wallet.example.com/api/tvc/enroll") {
          test.events.push("enrollment:descriptor");
          test.enrollBodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
          return Response.json({ descriptor });
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
  });

  it("verifies before authority, enrolls in one request, and returns only ownerAddress, keys, and zolana", async () => {
    const session = await open();

    expect(test.events).toEqual([
      "verify:deployment",
      "authorize",
      "enrollment:owner-signature",
      "enrollment:descriptor",
      "persist",
      "verify:operations",
      "owner-approval",
      "bootstrap",
      "persist",
    ]);
    expect(Object.keys(session).sort()).toEqual([
      "keys",
      "ownerAddress",
      "zolana",
    ]);
    expect(session).not.toHaveProperty("owner");
    expect(session).not.toHaveProperty("signal");
  });

  it("has the owner sign a Sign-In With Solana enrollment for the gateway's domain", async () => {
    await open();

    const [body] = test.enrollBodies;
    expect(Object.keys(body ?? {}).sort()).toEqual([
      "clientPublicKey",
      "issuedAtMs",
      "organizationId",
      "ownerSignature",
      "solanaAddress",
      "turnkeyWalletId",
    ]);
    expect(body).toMatchObject({
      organizationId: wallet.organizationId,
      turnkeyWalletId: wallet.walletId,
      solanaAddress: wallet.address,
      clientPublicKey: authorizer.clientPublicKey,
      ownerSignature: "77".repeat(64),
    });
    const { ownerSignature: _, ...enrollment } = body as Omit<WalletEnrollment, "domain"> & {
      ownerSignature: string;
    };
    expect(test.signedEnrollments).toEqual([
      walletEnrollmentMessage({ ...enrollment, domain: TVC_ENROLLMENT_DOMAIN }),
    ]);
  });

  it("builds every client against the gateway through the host's route, without a wallet grant", async () => {
    await open();

    const configs = vi.mocked(createTvcClient).mock.calls.map(([config]) => config);
    expect(configs).toHaveLength(2);
    for (const config of configs) {
      expect(config.backend).toEqual({
        kind: "gateway",
        endpoint: new URL("https://wallet.example.com/api/tvc"),
      });
    }
    expect(Object.keys(configs[1]?.operations ?? {}).sort()).toEqual([
      "authorizer",
      "walletDescriptor",
    ]);
    // Proofs post through the host's route, sealed for their route below the prover URL.
    // Under the policy file devnet publishes, which the enclave checks.
    expect(test.prover).toEqual({
      url: "https://wallet.example.com/api/tvc/zolana/prover",
      policy: expect.any(TvcProverPolicy),
    });
  });

  it("stores nothing when the gateway refuses the enrollment", async () => {
    vi.mocked(fetch).mockResolvedValue(
      Response.json({ code: "StaleEnrollment" }, { status: 400 }),
    );

    await expect(open()).rejects.toThrow("DescriptorProvisioningDenied");
    expect(test.saveState).not.toHaveBeenCalled();
  });

  it("reconnects a stored wallet without enrolling again", async () => {
    test.loadState.mockResolvedValue(storedState());
    test.loadIdentity.mockResolvedValue(identity);

    await open();

    expect(test.events).toEqual(["verify:operations", "authorize"]);
    expect(fetch).not.toHaveBeenCalled();
  });
});
