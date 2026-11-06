import { initializePoseidon } from "@heliuslabs/spr";
import { p256 } from "@noble/curves/p256";

import type { TvcBackend } from "../client/backend.js";
import type { TvcRequestSigner } from "../client/operation-executor.js";
import type { TvcRequestOptions } from "../client/request.js";
import { createTvcSession, type TvcSession } from "../client/session.js";
import type { TvcTransport } from "../client/transport.js";
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

export type TvcClientConfig = {
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
  /** The wallet descriptor enrollment answered for the signer's client key. */
  readonly descriptor: WalletDescriptor;
  /** Signs each request with the client key `descriptor` lists. */
  readonly signer: TvcRequestSigner;
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

/** What an application keeps to reopen a wallet, `keys.stored`. Neither part is a secret to the client. */
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
 * The enclave of one network, for the wallet of one descriptor. It verifies
 * the enclave on first use and holds that verification while it holds.
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
   * sealed seed opens without a call; otherwise the enclave bootstraps it,
   * and refuses an identity other than `stored.identity`. Persist
   * `keys.stored` after a bootstrap.
   */
  open(stored?: StoredWallet, options?: TvcOpenOptions): Promise<TvcKeys>;
};

/** `createTvcClient`'s configuration with the backend, release and prover spelled out, for tests. */
export type TestTvcClientConfig = Omit<TvcClientConfig, "endpoint" | "prover"> & {
  /** Where the client reaches the enclave: a tvc-gateway, or the enclave itself. */
  readonly backend: TvcBackend;
  /**
   * The release to verify the enclave against in place of the one this
   * package pins for `network`. Its policy must still name `network`.
   */
  readonly release?: ReleaseTrust;
  /** Defaults to `/v1/spr` beside the backend's endpoint, under the network's policy. */
  readonly prover?: TvcProverConfig;
};

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

export function clientFromSession(
  session: TvcSession,
  setup: {
    readonly network: Network;
    readonly servicePublicKey: string;
    readonly descriptor: WalletDescriptor;
    readonly prover: TvcProver;
  },
): TvcClient {
  const { descriptor, prover } = setup;

  /**
   * One operation over the verified connection. A refused or failed exchange
   * may mean the release moved on, such as to a new Quorum key epoch, so the
   * next call verifies again; a rate limit says nothing about the release.
   */
  async function run<TOperation extends Operation>(
    operation: TOperation,
    sealedSeed: SealedSeed | undefined,
    options?: OperationOptions,
  ) {
    const context = await session.context(options);
    try {
      return await executeOperation(context, operation, sealedSeed, options);
    } catch (error) {
      if (error instanceof TvcHttpError && error.status !== 429) session.forget(context);
      throw error;
    }
  }

  const enclave: TvcEnclave = {
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

  async function bootstrap(options: OperationOptions): Promise<BootstrapResult> {
    const result = await run({ type: "Bootstrap" }, undefined, options);
    if (result.solana_address !== descriptor.address) throw new TvcError("ReleaseBindingMismatch");
    return result;
  }

  async function bootstrapApproved(options: TvcOpenOptions = {}): Promise<BootstrapResult> {
    const { approve, ...request } = options;
    if (!approve) return bootstrap(request);
    // A release that fails verification never reaches the owner's approver.
    await session.context(request);
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
      if (identity.solanaAddress !== descriptor.address) {
        throw new TvcError("ShieldedIdentityChanged", "the stored identity is another wallet's");
      }
      await initializePoseidon();
      return new EnclaveKeys({ enclave, identity, sealedSeed, prover });
    },
  };
}

/** `createTestTvcClient` in `./testing`; `createTvcClient` is this with a gateway and the pinned release. */
export function createClient(config: TestTvcClientConfig): TvcClient {
  const network = requireNetwork(config.network);
  const release = config.release ?? releaseFor(network);
  const { descriptor, signer, backend, transport } = config;
  return clientFromSession(
    createTvcSession({
      network,
      backend,
      release,
      operations: { descriptor, signer },
      ...(config.nowMs === undefined ? {} : { nowMs: config.nowMs }),
      ...(transport === undefined ? {} : { transport }),
      ...(config.requestTimeoutMs === undefined ? {} : { requestTimeoutMs: config.requestTimeoutMs }),
    }),
    {
      network,
      servicePublicKey: turnkeyServicePublicKey(release.releasePolicy.policy.quorumPublicKey),
      descriptor,
      prover: proverFor(network, backend.endpoint, config.prover, transport),
    },
  );
}

/**
 * A client for the wallet `config.descriptor` names, through the tvc-gateway
 * at `config.endpoint`, verified against the release this package pins for
 * `config.network`. A network without a pinned release is `ReleaseNotPinned`.
 */
export function createTvcClient(config: TvcClientConfig): TvcClient {
  const { endpoint, prover, ...rest } = config;
  return createClient({
    ...rest,
    backend: { kind: "gateway", endpoint },
    ...(prover === undefined ? {} : { prover: { url: prover.href } }),
  });
}
