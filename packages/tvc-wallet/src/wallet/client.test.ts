import { ShieldedKeypair, initializePoseidon } from "@heliuslabs/spr";
import { p256 } from "@noble/curves/p256";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { OperationExecutionContext } from "../client/operation-executor.js";
import type { TvcSession } from "../client/session.js";
import { TvcError, TvcHttpError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { ReleaseTrust } from "../protocol/releases.js";
import type { BootstrapResult, WalletDescriptor } from "../protocol/types.js";
import {
  clientFromSession,
  createClient,
  createTvcClient,
  proverFor,
  type ShieldedIdentity,
} from "./client.js";
import { TvcProverPolicy } from "./prover-policy.js";

const execute = vi.hoisted(() => vi.fn());
vi.mock("./operations.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./operations.js")>()),
  executeOperation: execute,
}));

const signer = { clientKeyId: "client", signRequest: () => Promise.reject(new Error("unused")) };
const endpoint = new URL("https://devnet.helius-rpc.com/v1/private-wallet?api-key=key");

function wallet() {
  const address = ShieldedKeypair.generate().shieldedAddress();
  const identity: ShieldedIdentity = {
    solanaAddress: address.solanaAddress(),
    shieldedOwnerHash: encodeLowerHex(address.ownerHash()),
    shieldedNullifierPublicKey: encodeLowerHex(address.nullifierPublicKey),
    shieldedViewingPublicKey: encodeLowerHex(address.viewingPublicKey.toBytes()),
  };
  const bootstrap: BootstrapResult = {
    type: "Bootstrap",
    solana_address: identity.solanaAddress,
    shielded_owner_hash: identity.shieldedOwnerHash,
    shielded_nullifier_public_key: identity.shieldedNullifierPublicKey,
    shielded_viewing_public_key: identity.shieldedViewingPublicKey,
    sealed_seed: "ab".repeat(16),
    turnkey_activity_id: "activity",
  };
  const descriptor = { address: identity.solanaAddress, network: "devnet" } as WalletDescriptor;
  return { address, identity, bootstrap, descriptor };
}

/** A client over a session whose verification always holds, and whose operations `execute` answers. */
function fixture() {
  const { address, identity, bootstrap, descriptor } = wallet();
  const context = { verified: true } as unknown as OperationExecutionContext;
  const session = {
    context: vi.fn(async () => context),
    forget: vi.fn(),
  } satisfies TvcSession;
  const client = clientFromSession(session, {
    network: "devnet",
    servicePublicKey: "02".padEnd(66, "1"),
    descriptor,
    prover: { url: "https://prover.invalid/v1/spr", policy: new TvcProverPolicy("https://prover.invalid/policy") },
  });
  execute.mockReset();
  return { address, identity, bootstrap, client, session, context };
}

describe("open", () => {
  beforeAll(() => initializePoseidon());

  it("reopens a stored wallet without a call, and refuses another wallet's identity", async () => {
    const { address, identity, client, session } = fixture();
    const stored = { identity, sealedSeed: { sealedSeed: "cd".repeat(16) } };
    const keys = await client.open(stored);
    expect(keys.address().toBytes()).toEqual(address.toBytes());
    expect(keys.stored).toEqual(stored);
    expect(session.context).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();

    const other = wallet().identity;
    await expect(client.open({ identity: other, sealedSeed: stored.sealedSeed })).rejects.toMatchObject({
      code: "ShieldedIdentityChanged",
    });
    await expect(client.open({ identity, sealedSeed: { sealedSeed: "not hex" } })).rejects.toThrow();
  });

  it("bootstraps a wallet it has not stored, and pins a stored identity", async () => {
    const { identity, bootstrap, client, context } = fixture();
    execute.mockResolvedValue(bootstrap);
    const keys = await client.open();
    expect(execute).toHaveBeenCalledWith(context, { type: "Bootstrap" }, undefined, {});
    expect(keys.stored).toEqual({ identity, sealedSeed: { sealedSeed: bootstrap.sealed_seed } });

    // The recovery path: the identity alone bootstraps again, for that identity only.
    await expect(client.open({ identity })).resolves.toMatchObject({ stored: { identity } });
    await expect(client.open({ identity: wallet().identity })).rejects.toMatchObject({
      code: "ShieldedIdentityChanged",
    });
    execute.mockResolvedValue({ ...bootstrap, solana_address: wallet().identity.solanaAddress });
    await expect(client.open()).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
  });

  it("verifies before the approver runs, and hands it the bootstrap", async () => {
    const { bootstrap, client, session } = fixture();
    execute.mockResolvedValue(bootstrap);
    const controller = new AbortController();
    const approve = vi.fn(async (run: (signal?: AbortSignal) => Promise<void>, signal?: AbortSignal) => {
      expect(session.context).toHaveBeenCalledOnce();
      expect(execute).not.toHaveBeenCalled();
      expect(signal).toBe(controller.signal);
      await run(AbortSignal.timeout(60_000));
    });
    const keys = await client.open(undefined, { approve, signal: controller.signal, timeoutMs: 5_000 });
    expect(keys.stored.sealedSeed.sealedSeed).toBe(bootstrap.sealed_seed);
    const options = execute.mock.lastCall?.[3] as { signal: AbortSignal; timeoutMs: number };
    expect(options.timeoutMs).toBe(5_000);
    expect(options.signal.aborted).toBe(false);
    controller.abort();
    expect(options.signal.aborted).toBe(true);

    await expect(client.open(undefined, { approve: async () => {} })).rejects.toMatchObject({
      code: "BootstrapNotRun",
    });
    session.context.mockRejectedValueOnce(new TvcError("BootProofUnverified"));
    const refused = vi.fn();
    await expect(client.open(undefined, { approve: refused })).rejects.toMatchObject({
      code: "BootProofUnverified",
    });
    expect(refused).not.toHaveBeenCalled();
  });

  it("verifies again after the backend refuses or fails an operation, but not after a rate limit", async () => {
    const { identity, client, session, context } = fixture();
    const keys = await client.open({ identity, sealedSeed: { sealedSeed: "cd".repeat(16) } });
    const [viewingPublicKey] = keys.viewingPublicKeys();
    const request = [{ viewingPublicKey: viewingPublicKey!, firstNullifier: new Uint8Array(32) as never }];
    for (const [error, forgets] of [
      [new TvcHttpError("OperationRejected", 400, null), true],
      [new TvcHttpError("OperationUnavailable", 424, null), true],
      [new TvcHttpError("OperationRejected", 429, "1"), false],
      [new TvcError("ReleaseBindingMismatch"), false],
    ] as const) {
      session.forget.mockClear();
      execute.mockRejectedValueOnce(error);
      await expect(keys.transactionKeys(request)).rejects.toBe(error);
      if (forgets) expect(session.forget).toHaveBeenCalledWith(context);
      else expect(session.forget).not.toHaveBeenCalled();
    }
  });
});

describe("createTvcClient", () => {
  const descriptor = { address: "11111111111111111111111111111111", network: "devnet" } as WalletDescriptor;

  it("pins the package's release of its network and names its Turnkey service key", () => {
    expect(() => createTvcClient({ network: "mainnet", endpoint, descriptor, signer })).toThrowError(
      /ReleaseNotPinned/,
    );
    expect(() =>
      createTvcClient({ network: "testnet" as "devnet", endpoint, descriptor, signer }),
    ).toThrowError(/UnknownNetwork/);
    const client = createTvcClient({ network: "devnet", endpoint, descriptor, signer });
    expect(client.network).toBe("devnet");
    expect(client.servicePublicKey).toMatch(/^0[23][0-9a-f]{64}$/);

    const quorumSigning = p256.utils.randomPrivateKey();
    const quorumPublicKey = encodeLowerHex(
      Uint8Array.from([
        ...p256.getPublicKey(p256.utils.randomPrivateKey(), false),
        ...p256.getPublicKey(quorumSigning, false),
      ]),
    );
    const test = createClient({
      network: "mainnet",
      backend: { kind: "gateway", endpoint },
      descriptor,
      signer,
      release: { releasePolicy: { policy: { quorumPublicKey } } } as unknown as ReleaseTrust,
    });
    expect(test.servicePublicKey).toBe(encodeLowerHex(p256.getPublicKey(quorumSigning, true)));
  });

  it("proves beside the gateway under the network's policy unless told otherwise", () => {
    const forNetwork = vi.spyOn(TvcProverPolicy, "forNetwork");
    try {
      const transport = { fetch: vi.fn() };
      const beside = proverFor("devnet", endpoint, undefined, transport);
      expect(beside.url).toBe("https://devnet.helius-rpc.com/v1/spr?api-key=key");
      expect(beside.transport).toBe(transport);
      expect(forNetwork).toHaveBeenLastCalledWith("devnet", transport);

      const named = proverFor("mainnet", endpoint, { url: "https://prover.example/v1/spr" }, undefined);
      expect(named.url).toBe("https://prover.example/v1/spr");
      expect(forNetwork).toHaveBeenLastCalledWith("mainnet", undefined);

      const policy = new TvcProverPolicy("https://policy.example/devnet.json");
      expect(proverFor("devnet", endpoint, { url: "https://prover.example", policy }, undefined).policy).toBe(
        policy,
      );
      expect(forNetwork).toHaveBeenCalledTimes(2);
    } finally {
      forNetwork.mockRestore();
    }
  });
});
