import { p256 } from "@noble/curves/p256";

import type { TvcBackend } from "../client/backend.js";
import type { OperationsConfig } from "../client/operation-executor.js";
import type { TvcRequestOptions } from "../client/request.js";
import type { VerifiedConnection } from "../client/connection.js";
import { createTvcSession, type TvcSession } from "../client/session.js";
import type { TvcTransport } from "../client/transport.js";
import { parseQosP256Public } from "../crypto/qos.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { requireNetwork } from "../protocol/network.js";
import { releaseFor, type ReleaseTrust } from "../protocol/releases.js";
import type {
  BootstrapResult,
  SealedSeed,
  DecryptItem,
  DeriveItem,
  Network,
  ProverRequest,
  ProverSealing,
  SealedProverRequest,
  TransactionKeyItem,
} from "../protocol/types.js";
import {
  checkDecrypt,
  checkDerive,
  checkProve,
  checkTransactionKeys,
  executeOperation,
  type OperationOptions,
} from "./operations.js";

export type TvcClientConfig = {
  /**
   * The network the enclave serves. It picks the release this package pins
   * for it, and with it the Turnkey service key; `TvcKeys` downloads its
   * prover policy; enrollment signs for its chain.
   */
  readonly network: Network;
  /** Where the client reaches the enclave. */
  readonly backend: TvcBackend;
  /** Descriptor-bound authority for the wallet operations; absent for a verify-only client. */
  readonly operations?: OperationsConfig;
  /**
   * The release to verify the enclave against in place of the one this
   * package pins for `network`, for a local or test deployment. Its policy
   * must still name `network`.
   */
  readonly release?: ReleaseTrust;
  /**
   * Verifier clock. A function, not an instant: a fixed value would freeze
   * request timestamps and certificate-chain validation for the client's
   * whole life.
   */
  readonly nowMs?: () => bigint;
  readonly transport?: TvcTransport;
  /** Total deadline for each verification or operation, including proof lookup. Defaults to two minutes. */
  readonly requestTimeoutMs?: number;
};

/**
 * The wallet's public shielded identity.
 *
 * The sealed seed is a replaceable cache, not the root of recovery: the
 * seed is a deterministic Turnkey signature over a fixed message, so
 * re-running bootstrap against a new release re-derives the same identity.
 * Pass the identity observed before, and bootstrap refuses to adopt another.
 */
export type ShieldedIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

export type BootstrapOptions = OperationOptions & {
  readonly expectedIdentity?: ShieldedIdentity;
};

/**
 * The five enclave operations over one verified connection, on the wire's
 * terms. `TvcKeys` is the same surface as the Zolana SDK's `WalletKeys`, which
 * is what an application normally holds. Every call but `bootstrap` presents
 * the sealed seed the bootstrap returned; the enclave cannot use it under
 * another descriptor or past a Quorum key rotation.
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
  connectAndVerify(options?: TvcRequestOptions): Promise<VerifiedConnection>;
  /** Derives the shielded identity and returns it sealed. Also the recovery path. */
  bootstrap(connection: VerifiedConnection, options?: BootstrapOptions): Promise<BootstrapResult>;
  /** Opens each ciphertext with the wallet's viewing key; one plaintext per item. */
  decrypt(
    connection: VerifiedConnection,
    sealedSeed: SealedSeed,
    items: readonly DecryptItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Derives nullifiers and merge values; one value per item. */
  derive(
    connection: VerifiedConnection,
    sealedSeed: SealedSeed,
    items: readonly DeriveItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Mints per-transaction viewing secrets; one per item. */
  transactionKeys(
    connection: VerifiedConnection,
    sealedSeed: SealedSeed,
    items: readonly TransactionKeyItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /**
   * Completes the prover request with the nullifier secret and seals it to the
   * prover `prover` attests; the client posts the sealed request.
   */
  prove(
    connection: VerifiedConnection,
    sealedSeed: SealedSeed,
    request: ProverRequest,
    prover: ProverSealing,
    options?: OperationOptions,
  ): Promise<SealedProverRequest>;
};

export function identityOf(result: BootstrapResult): ShieldedIdentity {
  return Object.freeze({
    solanaAddress: result.solana_address,
    shieldedOwnerHash: result.shielded_owner_hash,
    shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
    shieldedViewingPublicKey: result.shielded_viewing_public_key,
  });
}

export function sealedSeedOf(result: BootstrapResult): SealedSeed {
  requireHex(result.sealed_seed);
  return Object.freeze({ sealedSeed: result.sealed_seed });
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

export function clientFromSession(
  session: TvcSession,
  network: Network,
  servicePublicKey: string,
): TvcClient {
  return {
    network,
    servicePublicKey,
    connectAndVerify: (options) => session.connectAndVerify(options),

    async bootstrap(connection, options) {
      const context = session.requireOperationContext(connection);
      const result = await executeOperation(context, { type: "Bootstrap" }, undefined, options);
      if (result.solana_address !== context.operations.walletDescriptor.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      if (options?.expectedIdentity && !sameIdentity(identityOf(result), options.expectedIdentity)) {
        throw new TvcError("ShieldedIdentityChanged");
      }
      return result;
    },

    async decrypt(connection, sealedSeed, items, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkDecrypt({ type: "Decrypt", items }),
        sealedSeed,
        options,
      );
      return result.plaintexts;
    },

    async derive(connection, sealedSeed, items, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkDerive({ type: "Derive", items }),
        sealedSeed,
        options,
      );
      return result.values;
    },

    async transactionKeys(connection, sealedSeed, items, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkTransactionKeys({ type: "TransactionKeys", items }),
        sealedSeed,
        options,
      );
      return result.secrets;
    },

    async prove(connection, sealedSeed, request, prover, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkProve({ type: "Prove", request, prover }),
        sealedSeed,
        options,
      );
      return result.sealed;
    },
  };
}

/**
 * A client for the enclave of `config.network`, verified against the release
 * this package pins for it or `config.release`. A network without a pinned
 * release needs `config.release`.
 */
export function createTvcClient(config: TvcClientConfig): TvcClient {
  const network = requireNetwork(config.network);
  const release = config.release ?? releaseFor(network);
  return clientFromSession(
    createTvcSession({ ...config, network, release }),
    network,
    turnkeyServicePublicKey(release.releasePolicy.policy.quorumPublicKey),
  );
}
