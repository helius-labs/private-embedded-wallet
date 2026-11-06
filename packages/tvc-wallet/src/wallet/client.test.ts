import { ShieldedKeypair, initializePoseidon } from "@heliuslabs/spr";
import { p256 } from "@noble/curves/p256";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { ConnectedTvcRuntime } from "../client/connection.js";
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
import { fixedClientKeys, type TvcClientKey, type TvcClientKeys } from "./client-keys.js";
import { TvcProverPolicy } from "./prover-policy.js";
import type { TvcTurnkey } from "./turnkey.js";

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

const prover = { url: "https://prover.invalid/v1/spr", policy: new TvcProverPolicy("https://prover.invalid/policy") };

/** A session whose verification always holds until it is reset. */
function verifiedSession() {
  let current = { verified: 1 } as unknown as ConnectedTvcRuntime;
  const session = {
    context: vi.fn(async () => current),
    forget: vi.fn(),
    reset: vi.fn(() => {
      current = { verified: (current as unknown as { verified: number }).verified + 1 } as unknown as ConnectedTvcRuntime;
    }),
  } satisfies TvcSession;
  return session;
}

/** A client over a session whose verification always holds, and whose operations `execute` answers. */
function fixture() {
  const { address, identity, bootstrap, descriptor } = wallet();
  const session = verifiedSession();
  const operations = { descriptor, signer };
  const client = clientFromSession(session, {
    network: "devnet",
    servicePublicKey: "02".padEnd(66, "1"),
    keys: fixedClientKeys(operations),
    prover,
  });
  execute.mockReset();
  const context = expect.objectContaining({ verified: 1, operations });
  return { address, identity, bootstrap, client, session, context, operations };
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
    const { identity, client, session } = fixture();
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
      if (forgets) expect(session.forget).toHaveBeenCalledWith({ verified: 1 });
      else expect(session.forget).not.toHaveBeenCalled();
    }
  });
});

describe("a client key that changes", () => {
  beforeAll(() => initializePoseidon());

  /** Keys whose current key the test switches, each with its own descriptor of the same wallet. */
  function switchingKeys(address: string) {
    const enrolled: string[] = [];
    const descriptorOf = (id: string) =>
      ({ address, network: "devnet", allowed_clients: [{ client_public_key: id }] }) as unknown as WalletDescriptor;
    const key = (id: string): TvcClientKey => ({
      id,
      operations: vi.fn(async () => {
        enrolled.push(id);
        return { descriptor: descriptorOf(id), signer: { ...signer, clientKeyId: id } };
      }),
    });
    const available = { a: key("a"), b: key("b") };
    let current: TvcClientKey = available.a;
    const keys: TvcClientKeys = { current: vi.fn(async () => current) };
    return { keys, enrolled, use: (id: "a" | "b") => { current = available[id]; } };
  }

  it("verifies again for the new key, and opens a stored seed with any key of the wallet", async () => {
    const { identity, bootstrap } = wallet();
    const session = verifiedSession();
    const { keys, enrolled, use } = switchingKeys(identity.solanaAddress);
    const client = clientFromSession(session, { network: "devnet", servicePublicKey: "02".padEnd(66, "1"), keys, prover });
    execute.mockReset();
    execute.mockResolvedValue(bootstrap);
    const opened = await client.open();
    expect(execute.mock.lastCall?.[0]).toMatchObject({ verified: 1, operations: { signer: { clientKeyId: "a" } } });
    expect(session.reset).not.toHaveBeenCalled();

    // A new login: the stored seed opens without a call, and the next
    // operation verifies again and signs with the new key.
    use("b");
    const reopened = await client.open(opened.stored);
    expect(session.context).toHaveBeenCalledOnce();
    const [viewingPublicKey] = reopened.viewingPublicKeys();
    const request = [{ viewingPublicKey: viewingPublicKey!, firstNullifier: new Uint8Array(32) as never }];
    execute.mockResolvedValue({ type: "TransactionKeys", secrets: ["00".repeat(32)] });
    await reopened.transactionKeys(request);
    expect(session.reset).toHaveBeenCalledOnce();
    expect(execute.mock.lastCall?.[0]).toMatchObject({ verified: 2, operations: { signer: { clientKeyId: "b" } } });
    expect(execute.mock.lastCall?.[2]).toEqual(opened.stored.sealedSeed);

    // The same key again keeps the verification.
    await reopened.transactionKeys(request);
    expect(session.reset).toHaveBeenCalledOnce();
    expect(enrolled).toEqual(["a", "b", "b"]);
  });

  it("refuses to send a stored wallet's seed under another wallet's descriptor", async () => {
    const { identity } = wallet();
    const { keys } = switchingKeys(wallet().identity.solanaAddress);
    const client = clientFromSession(verifiedSession(), { network: "devnet", servicePublicKey: "02".padEnd(66, "1"), keys, prover });
    execute.mockReset();
    const opened = await client.open({ identity, sealedSeed: { sealedSeed: "cd".repeat(16) } });
    const [viewingPublicKey] = opened.viewingPublicKeys();
    await expect(
      opened.transactionKeys([{ viewingPublicKey: viewingPublicKey!, firstNullifier: new Uint8Array(32) as never }]),
    ).rejects.toMatchObject({ code: "ShieldedIdentityChanged" });
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("createTvcClient", () => {
  const descriptor = { address: "11111111111111111111111111111111", network: "devnet" } as WalletDescriptor;
  const turnkey: TvcTurnkey = {
    getSession: () => Promise.resolve(undefined),
    signWithApiKey: () => Promise.reject(new Error("unused")),
    fetchWallets: () => Promise.reject(new Error("unused")),
    signMessage: () => Promise.reject(new Error("unused")),
  };

  it("pins the package's release of its network and names its Turnkey service key", () => {
    expect(() => createTvcClient({ network: "mainnet", endpoint, turnkey })).toThrowError(
      /ReleaseNotPinned/,
    );
    expect(() =>
      createTvcClient({ network: "testnet" as "devnet", endpoint, turnkey }),
    ).toThrowError(/UnknownNetwork/);
    const client = createTvcClient({ network: "devnet", endpoint, turnkey });
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
    expect(() =>
      createClient({
        network: "devnet",
        backend: { kind: "enclave", endpoint },
        turnkey,
      }),
    ).toThrowError(/GatewayRequired/);
  });

  it("says so when no Turnkey session is active, before it verifies", async () => {
    const fetch = vi.fn();
    const client = createTvcClient({ network: "devnet", endpoint, turnkey, transport: { fetch } });
    await expect(client.open()).rejects.toMatchObject({ code: "TurnkeySessionRequired" });
    expect(fetch).not.toHaveBeenCalled();
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
