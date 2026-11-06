import { initializePoseidon } from "@heliuslabs/spr";
import { p256 } from "@noble/curves/p256";

import type { TvcBackend } from "../client/backend.js";
import type { ConnectedTvcRuntime } from "../client/connection.js";
import type { OperationExecutionContext, TvcRequestSigner } from "../client/operation-executor.js";
import { requestScope, type TvcRequestOptions } from "../client/request.js";
import { createTvcSession, type TvcSession } from "../client/session.js";
import { createDefaultTransport, type TvcTransport } from "../client/transport.js";
import { parseQosP256Public } from "../crypto/qos.js";
import { TvcError, TvcHttpError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { requireNetwork } from "../protocol/network.js";
import { releaseFor, type ReleaseTrust } from "../protocol/releases.js";
import type {
  BootstrapResult,
  Network,
  Operation,
  SealedSeed,
  WalletDescriptor,
} from "../protocol/types.js";
import { fixedClientKeys, type TvcClientKey, type TvcClientKeys } from "./client-keys.js";
import { EnclaveKeys, type TvcEnclave, type TvcKeys } from "./keys.js";
import {
  checkDecrypt,
  checkDerive,
  checkProve,
  checkTransactionKeys,
  executeOperation,
  type OperationOptions,
} from "./operations.js";
import type { TvcProver, TvcProverConfig } from "./prover.js";
import { TvcProverPolicy } from "./prover-policy.js";
import { turnkeyClientKeys, type TvcTurnkey, type TvcTurnkeyWalletAccount } from "./turnkey.js";

export type TvcClientConfig<Account extends TvcTurnkeyWalletAccount = TvcTurnkeyWalletAccount> = {
  /**
   * The network the enclave serves. It picks the release this package pins
   * for it, and with it the Turnkey service key, and the prover policy.
   */
  readonly network: Network;
  /**
   * The tvc-gateway: `https://<network>.helius-rpc.com/v1/private-wallet?api-key=…`,
   * or an application's proxy of it. Its query travels on every route.
   */
  readonly endpoint: URL;
  /**
   * The application's Turnkey client, logged in: `@turnkey/core`'s
   * `TurnkeyClient` or `useTurnkey()` as they are. Its session key signs every
   * request; the client enrolls each session key with the gateway on first
   * use, the wallet owner signing the enrollment.
   */
  readonly turnkey: TvcTurnkey<Account>;
  /**
   * The wallet's Solana address, to name one when the session's organization
   * holds more than one Solana account. Defaults to its only one.
   */
  readonly solanaAddress?: string;
  /**
   * The attested prover the enclave seals proofs to and the client posts them
   * to. Defaults to `/v1/spr` on the endpoint's origin with the endpoint's
   * query, where Helius serves the network's TEE prover.
   */
  readonly prover?: URL;
  /**
   * Verifier clock. A function, not an instant: a fixed value would freeze
   * request timestamps and certificate-chain validation for the client's
   * whole life.
   */
  readonly nowMs?: () => bigint;
  /** Every HTTP request the client makes: the gateway, the prover and its policy file. */
  readonly transport?: TvcTransport;
  /** Total deadline for each verification or operation, including proof lookup. Defaults to two minutes. */
  readonly requestTimeoutMs?: number;
};

/**
 * The wallet's public shielded identity.
 *
 * The sealed seed is a replaceable cache, not the root of recovery: the
 * seed is a deterministic Turnkey signature over a fixed message, so
 * bootstrapping again against a new release re-derives the same identity.
 */
export type ShieldedIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

/**
 * What an application keeps to reopen a wallet, `keys.stored`. Sensitive: with
 * a current descriptor of the wallet and its client key, or with tvc-gateway's
 * provisioning key, the sealed seed lets the enclave decrypt, derive and prove
 * for the wallet, until that descriptor expires or for as long as that key
 * issues descriptors. Keep it like the user's session, out of logs and shared
 * storage.
 */
export type StoredWallet = {
  readonly identity: ShieldedIdentity;
  /**
   * The seed the enclave sealed for the wallet, presented on every call.
   * Without it `open` bootstraps again and accepts only `identity`: the
   * recovery path after the seed is lost or a Quorum key rotation retired it.
   */
  readonly sealedSeed?: SealedSeed;
};

/** Applies to the verification and to the bootstrap, each. */
export type TvcOpenOptions = TvcRequestOptions & {
  /**
   * Runs `bootstrap` while the wallet owner approves the Turnkey activity it
   * starts, for a wallet whose Turnkey policy requires the owner to co-sign
   * the enclave's bootstrap signature. Called only when `open` bootstraps,
   * after the enclave verified.
   */
  readonly approve?: (
    bootstrap: (signal?: AbortSignal) => Promise<void>,
    signal?: AbortSignal,
  ) => Promise<void>;
};

/**
 * The enclave of one network, for one Turnkey wallet. It verifies the enclave
 * on first use and holds that verification while it holds; it verifies again
 * when the session key changes.
 */
export type TvcClient = {
  /** The network the enclave serves. */
  readonly network: Network;
  /**
   * The Turnkey API key the enclave signs the bootstrap message with, as
   * compressed P-256 hex: the signing half of the release's Quorum key. The
   * wallet's bootstrap policy names the user that holds it.
   */
  readonly servicePublicKey: string;
  /**
   * The wallet's keys, the SDK's `WalletKeys`. A `stored` wallet with its
   * sealed seed opens without a call, and serves under any session key of
   * the wallet; otherwise the enclave bootstraps it, and refuses an identity
   * other than `stored.identity`. Persist `keys.stored` after a bootstrap.
   */
  open(stored?: StoredWallet, options?: TvcOpenOptions): Promise<TvcKeys>;
};

/**
 * The request key of a test client: the Turnkey session, through a gateway, as
 * `createTvcClient` has it, or a descriptor and the signer of the key it lists.
 */
export type TestTvcClientKey<Account extends TvcTurnkeyWalletAccount = TvcTurnkeyWalletAccount> =
  | Pick<TvcClientConfig<Account>, "turnkey" | "solanaAddress">
  | {
      /** A wallet descriptor that lists `signer`'s key. */
      readonly descriptor: WalletDescriptor;
      readonly signer: TvcRequestSigner;
    };

/** `createTvcClient`'s configuration with the backend, release and prover spelled out, for tests. */
export type TestTvcClientConfig<Account extends TvcTurnkeyWalletAccount = TvcTurnkeyWalletAccount> = Pick<
  TvcClientConfig<Account>,
  "network" | "nowMs" | "transport" | "requestTimeoutMs"
> & {
  /** Where the client reaches the enclave: a tvc-gateway, or the enclave itself. */
  readonly backend: TvcBackend;
  /**
   * The release to verify the enclave against in place of the one this
   * package pins for `network`. Its policy must still name `network`.
   */
  readonly release?: ReleaseTrust;
  /** Defaults to `/v1/spr` beside the backend's endpoint, under the network's policy. */
  readonly prover?: TvcProverConfig;
} & TestTvcClientKey<Account>;

function identityOf(result: BootstrapResult): ShieldedIdentity {
  return Object.freeze({
    solanaAddress: result.solana_address,
    shieldedOwnerHash: result.shielded_owner_hash,
    shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
    shieldedViewingPublicKey: result.shielded_viewing_public_key,
  });
}

function sameIdentity(a: ShieldedIdentity, b: ShieldedIdentity): boolean {
  return (
    a.solanaAddress === b.solanaAddress &&
    a.shieldedOwnerHash === b.shieldedOwnerHash &&
    a.shieldedNullifierPublicKey === b.shieldedNullifierPublicKey &&
    a.shieldedViewingPublicKey === b.shieldedViewingPublicKey
  );
}

/** The compressed signing half of a QOS public key, which Turnkey names an API key by. */
export function turnkeyServicePublicKey(quorumPublicKey: string): string {
  let signing: Uint8Array;
  try {
    signing = parseQosP256Public(decodeLowerHex(quorumPublicKey)).signing;
  } catch {
    throw new TvcError("ReleasePolicyInvalid", "the Quorum public key is not two P-256 points");
  }
  return encodeLowerHex(p256.ProjectivePoint.fromHex(signing).toRawBytes(true));
}

/** `/v1/spr` on the origin of `endpoint`, with its query: where gatekeeper serves the TEE prover beside the gateway. */
function proverBeside(endpoint: URL): string {
  const url = new URL("/v1/spr", endpoint);
  url.search = endpoint.search;
  return url.href;
}

/** The prover a client's wallets prove through, sharing one policy download. */
export function proverFor(
  network: Network,
  endpoint: URL,
  config: TvcProverConfig | undefined,
  transport: TvcTransport | undefined,
): TvcProver {
  const proverTransport = config?.transport ?? transport;
  return {
    url: config?.url ?? proverBeside(endpoint),
    policy: config?.policy ?? TvcProverPolicy.forNetwork(network, proverTransport),
    ...(proverTransport ? { transport: proverTransport } : {}),
  };
}

function signalOf(...signals: (AbortSignal | undefined)[]): AbortSignal | undefined {
  const present = signals.filter((signal) => signal !== undefined);
  return present.length > 1 ? AbortSignal.any(present) : present[0];
}

/** Where a client's request key comes from: the Turnkey session, enrolled through a gateway, or a fixed key. */
export function clientKeysOf<Account extends TvcTurnkeyWalletAccount>(
  key: TestTvcClientKey<Account>,
  setup: {
    readonly network: Network;
    readonly backend: TvcBackend;
    readonly transport?: TvcTransport | undefined;
    readonly nowMs?: (() => bigint) | undefined;
  },
): TvcClientKeys {
  if (!("turnkey" in key)) return fixedClientKeys({ descriptor: key.descriptor, signer: key.signer });
  if (setup.backend.kind !== "gateway") {
    throw new TvcError("GatewayRequired", "a Turnkey session key enrolls through a tvc-gateway");
  }
  return turnkeyClientKeys({
    turnkey: key.turnkey,
    network: setup.network,
    endpoint: setup.backend.endpoint,
    ...(key.solanaAddress === undefined ? {} : { solanaAddress: key.solanaAddress }),
    transport: setup.transport ?? createDefaultTransport(),
    nowMs: setup.nowMs ?? (() => BigInt(Date.now())),
  });
}

export function clientFromSession(
  session: TvcSession,
  setup: {
    readonly network: Network;
    readonly servicePublicKey: string;
    readonly keys: TvcClientKeys;
    readonly prover: TvcProver;
    readonly requestTimeoutMs?: number | undefined;
  },
): TvcClient {
  const { keys, prover } = setup;
  /** The key the current verification was made for. */
  let verifiedFor: string | undefined;

  type Prepared = {
    readonly runtime: ConnectedTvcRuntime;
    readonly context: OperationExecutionContext;
    readonly key: TvcClientKey;
  };

  /**
   * The verified connection and the current request key, enrolled. A key
   * other than the last one's, after a new login, verifies the enclave again.
   * A release that fails verification enrolls nothing.
   */
  async function prepare(options: OperationOptions = {}): Promise<Prepared> {
    const scope = requestScope(options, setup.requestTimeoutMs);
    try {
      const key = await keys.current(scope.signal);
      if (verifiedFor !== key.id) {
        if (verifiedFor !== undefined) session.reset();
        verifiedFor = key.id;
      }
      const runtime = await session.context({ ...options, signal: scope.signal });
      const operations = await key.operations(scope.signal);
      return { runtime, context: { ...runtime, operations }, key };
    } finally {
      scope.dispose();
    }
  }

  /**
   * One operation over the verified connection. A refused or failed exchange
   * may mean the release moved on, such as to a new Quorum key epoch, so the
   * next call verifies again; a rate limit or an expired descriptor says
   * nothing about the release.
   */
  async function execute<TOperation extends Operation>(
    prepared: Prepared,
    operation: TOperation,
    sealedSeed: SealedSeed | undefined,
    options?: OperationOptions,
  ) {
    try {
      return await executeOperation(prepared.context, operation, sealedSeed, options);
    } catch (error) {
      if (error instanceof TvcHttpError && error.status !== 429 && error.code !== "DescriptorExpired") {
        session.forget(prepared.runtime);
      }
      throw error;
    }
  }

  /**
   * `attempt` with the current key's descriptor, and once more after the key
   * enrolls again when the backend refused that descriptor as expired, such
   * as on a clock that runs behind the gateway's.
   */
  async function enrolled<T>(options: OperationOptions | undefined, attempt: (prepared: Prepared) => Promise<T>) {
    const prepared = await prepare(options);
    try {
      return await attempt(prepared);
    } catch (error) {
      if (!(error instanceof TvcError) || error.code !== "DescriptorExpired" || !prepared.key.expire) throw error;
      prepared.key.expire(prepared.context.operations.descriptor);
      return attempt(await prepare(options));
    }
  }

  /** The key operations of the wallet at `solanaAddress`, which the current key's descriptor must name. */
  function enclaveFor(solanaAddress: string): TvcEnclave {
    async function run<TOperation extends Operation>(
      operation: TOperation,
      sealedSeed: SealedSeed,
      options?: OperationOptions,
    ) {
      return enrolled(options, (prepared) => {
        if (prepared.context.operations.descriptor.address !== solanaAddress) {
          throw new TvcError("ShieldedIdentityChanged", "the stored identity is another wallet's");
        }
        return execute(prepared, operation, sealedSeed, options);
      });
    }
    return {
      async decrypt(sealedSeed, items, options) {
        return (await run(checkDecrypt({ type: "Decrypt", items }), sealedSeed, options)).plaintexts;
      },
      async derive(sealedSeed, items, options) {
        return (await run(checkDerive({ type: "Derive", items }), sealedSeed, options)).values;
      },
      async transactionKeys(sealedSeed, items, options) {
        return (
          await run(checkTransactionKeys({ type: "TransactionKeys", items }), sealedSeed, options)
        ).secrets;
      },
      async prove(sealedSeed, request, sealing, options) {
        return (await run(checkProve({ type: "Prove", request, prover: sealing }), sealedSeed, options)).sealed;
      },
    };
  }

  async function bootstrap(options: OperationOptions): Promise<BootstrapResult> {
    return enrolled(options, async (prepared) => {
      const result = await execute(prepared, { type: "Bootstrap" }, undefined, options);
      if (result.solana_address !== prepared.context.operations.descriptor.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      return result;
    });
  }

  async function bootstrapApproved(options: TvcOpenOptions = {}): Promise<BootstrapResult> {
    const { approve, ...request } = options;
    if (!approve) return bootstrap(request);
    // A release that fails verification never reaches the owner's approver.
    await prepare(request);
    let result: BootstrapResult | undefined;
    await approve(async (signal) => {
      const combined = signalOf(request.signal, signal);
      result = await bootstrap({ ...request, ...(combined ? { signal: combined } : {}) });
    }, request.signal);
    if (result === undefined) throw new TvcError("BootstrapNotRun", "approve returned without running bootstrap");
    return result;
  }

  return {
    network: setup.network,
    servicePublicKey: setup.servicePublicKey,

    async open(stored, options) {
      let identity: ShieldedIdentity;
      let sealedSeed: SealedSeed;
      if (stored?.sealedSeed) {
        identity = stored.identity;
        requireHex(stored.sealedSeed.sealedSeed);
        sealedSeed = Object.freeze({ sealedSeed: stored.sealedSeed.sealedSeed });
      } else {
        const result = await bootstrapApproved(options);
        identity = identityOf(result);
        if (stored && !sameIdentity(identity, stored.identity)) {
          throw new TvcError("ShieldedIdentityChanged");
        }
        requireHex(result.sealed_seed);
        sealedSeed = Object.freeze({ sealedSeed: result.sealed_seed });
      }
      if (keys.solanaAddress !== undefined && identity.solanaAddress !== keys.solanaAddress) {
        throw new TvcError("ShieldedIdentityChanged", "the stored identity is another wallet's");
      }
      await initializePoseidon();
      return new EnclaveKeys({ enclave: enclaveFor(identity.solanaAddress), identity, sealedSeed, prover });
    },
  };
}

/** `createTestTvcClient` in `./testing`; `createTvcClient` is this with a gateway and the pinned release. */
export function createClient<Account extends TvcTurnkeyWalletAccount>(
  config: TestTvcClientConfig<Account>,
): TvcClient {
  const network = requireNetwork(config.network);
  const release = config.release ?? releaseFor(network);
  const { backend, transport, nowMs, requestTimeoutMs } = config;
  return clientFromSession(
    createTvcSession({
      network,
      backend,
      release,
      ...(nowMs === undefined ? {} : { nowMs }),
      ...(transport === undefined ? {} : { transport }),
      ...(requestTimeoutMs === undefined ? {} : { requestTimeoutMs }),
    }),
    {
      network,
      servicePublicKey: turnkeyServicePublicKey(release.releasePolicy.policy.quorumPublicKey),
      keys: clientKeysOf(config, { network, backend, transport, nowMs }),
      prover: proverFor(network, backend.endpoint, config.prover, transport),
      requestTimeoutMs,
    },
  );
}

/**
 * A client for the wallet of the logged-in Turnkey session, through the
 * tvc-gateway at `config.endpoint`, verified against the release this package
 * pins for `config.network`. A network without a pinned release is
 * `ReleaseNotPinned`.
 */
export function createTvcClient<Account extends TvcTurnkeyWalletAccount>(
  config: TvcClientConfig<Account>,
): TvcClient {
  // Only the fields above: a caller's `release`, `backend` or descriptor must
  // not reach `createClient`, which would trust them in place of the pin.
  const { network, endpoint, turnkey, solanaAddress, prover, nowMs, transport, requestTimeoutMs } = config;
  return createClient<Account>({
    network,
    backend: { kind: "gateway", endpoint },
    turnkey,
    solanaAddress,
    ...(prover === undefined ? {} : { prover: { url: prover.href } }),
    nowMs,
    transport,
    requestTimeoutMs,
  });
}
