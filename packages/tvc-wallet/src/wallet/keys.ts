import {
  ViewingKey,
  type Bytes32,
  type DecryptRequest,
  type DeriveRequest,
  type RequestContext,
  type ShieldedAddress,
  type WalletKeys,
} from "@heliuslabs/spr";
import {
  mergeProverRequestBody,
  parseProof,
  proverRequestBody,
  type MergeInputs,
  type Proof,
  type ProverInputs,
} from "@heliuslabs/spr/client";
import type { X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { TransactionKeyRequest } from "@heliuslabs/spr/transaction";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError, TvcOperationError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type {
  SealedSeed,
  DecryptItem,
  DecryptLabel,
  DeriveItem,
  ProverRequest,
  TransactionKeyItem,
} from "../protocol/types.js";
import type { ShieldedIdentity, TvcClient } from "./client.js";
import { shieldedAddressOf } from "./identity.js";
import { MAX_ITEMS_PER_BATCH, type OperationOptions } from "./operations.js";
import {
  fetchAttestation,
  sealingFor,
  submitSealed,
  type ProverAttestation,
  type TvcProverConfig,
} from "./prover.js";
import { TvcProverPolicy, attestationReuseMs, type HeldProverPolicy } from "./prover-policy.js";

export type TvcKeysInput = {
  readonly client: TvcClient;
  readonly connection: VerifiedConnection;
  /** The sealed seed `bootstrap` returned. */
  readonly sealedSeed: SealedSeed;
  /** The identity `bootstrap` returned; see `shieldedAddressOf`. */
  readonly identity: ShieldedIdentity;
  /**
   * The attested prover proofs are sealed to and posted at, under the signed
   * policy of the client's network unless it names another.
   */
  readonly prover: TvcProverConfig;
};

const LABELS: Record<DecryptRequest["label"], DecryptLabel> = {
  transfer: "Transfer",
  ringDeposit: "RingDeposit",
};

/**
 * The SDK's cancellation and deadline, as one signal for the enclave call. Built
 * once per SDK request, so a deadline covers every batch the request splits into.
 */
function operationOptions(context: RequestContext | undefined): OperationOptions {
  const signals: AbortSignal[] = [];
  if (context?.signal) signals.push(context.signal);
  if (context?.timeoutMs !== undefined) signals.push(AbortSignal.timeout(context.timeoutMs));
  if (signals.length === 0) return {};
  return { signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals),
    ...(context?.timeoutMs === undefined ? {} : { timeoutMs: context.timeoutMs }) };
}

/**
 * The Zolana SDK's `WalletKeys`, answered by the enclave. Hand it to
 * `syncWallet`, `buildTransferTransaction`, and every other SDK flow in place
 * of `LocalKeys`: each SDK request becomes one enclave operation per batch.
 * A proof's witness is completed with the nullifier secret inside the enclave
 * and sealed there to an attested prover; this client posts the sealed
 * request and never sees the secret. Nothing here signs; the application's
 * Solana signer does.
 */
export class TvcKeys implements WalletKeys {
  readonly #client: TvcClient;
  readonly #connection: VerifiedConnection;
  readonly #sealedSeed: SealedSeed;
  readonly #address: ShieldedAddress;
  readonly #prover: TvcProverConfig;
  readonly #policy: TvcProverPolicy;
  #attested: ProverAttestation | undefined;

  constructor(input: TvcKeysInput) {
    this.#client = input.client;
    this.#connection = input.connection;
    this.#sealedSeed = input.sealedSeed;
    this.#address = shieldedAddressOf(input.identity);
    this.#prover = input.prover;
    this.#policy = input.prover.policy ?? TvcProverPolicy.forNetwork(input.client.network);
  }

  address(): ShieldedAddress {
    return this.#address;
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return [this.#address.viewingPublicKey];
  }

  async decrypt(
    requests: readonly DecryptRequest[],
    context?: RequestContext,
  ): Promise<readonly Uint8Array[]> {
    const options = operationOptions(context);
    const plaintexts = await this.#batched(
      requests.map(
        (request): DecryptItem => ({
          ciphertext: encodeLowerHex(request.ciphertext),
          viewing_public_key: encodeLowerHex(request.viewingPublicKey.toBytes()),
          transaction_viewing_public_key: encodeLowerHex(request.txViewingPublicKey.toBytes()),
          salt: encodeLowerHex(request.salt),
          slot_index: String(request.slotIndex),
          label: LABELS[request.label],
        }),
      ),
      (items) => this.#client.decrypt(this.#connection, this.#sealedSeed, items, options),
    );
    return plaintexts.map(decodeLowerHex);
  }

  async derive(
    requests: readonly DeriveRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]> {
    const options = operationOptions(context);
    const values = await this.#batched(
      requests.map((request): DeriveItem => {
        switch (request.kind) {
          case "nullifier":
            return {
              kind: "Nullifier",
              utxo_hash: encodeLowerHex(request.utxoHash),
              blinding: encodeLowerHex(request.blinding),
            };
          case "mergeDummyNullifier":
            return {
              kind: "MergeDummyNullifier",
              first_nullifier: encodeLowerHex(request.firstNullifier),
              slot_index: encodeDecimalU64(BigInt(request.slotIndex)),
            };
          case "mergeOutputBlinding":
            return {
              kind: "MergeOutputBlinding",
              first_nullifier: encodeLowerHex(request.firstNullifier),
            };
          case "mergePrivateTxBlinding":
            return {
              kind: "MergePrivateTxBlinding",
              first_nullifier: encodeLowerHex(request.firstNullifier),
            };
          case "mergeOutputKey":
            return {
              kind: "MergeOutputKey",
              first_nullifier: encodeLowerHex(request.firstNullifier),
            };
        }
      }),
      (items) => this.#client.derive(this.#connection, this.#sealedSeed, items, options),
    );
    return values.map((value) => decodeLowerHex(value) as Bytes32);
  }

  async transactionKeys(
    requests: readonly TransactionKeyRequest[],
    context?: RequestContext,
  ): Promise<readonly ViewingKey[]> {
    const options = operationOptions(context);
    const secrets = await this.#batched(
      requests.map(
        (request): TransactionKeyItem => ({
          viewing_public_key: encodeLowerHex(request.viewingPublicKey.toBytes()),
          first_nullifier: encodeLowerHex(request.firstNullifier),
        }),
      ),
      (items) => this.#client.transactionKeys(this.#connection, this.#sealedSeed, items, options),
    );
    const keys: ViewingKey[] = [];
    try {
      for (const secret of secrets) keys.push(ViewingKey.fromBytes(decodeLowerHex(secret) as Bytes32));
    } catch (cause) {
      for (const key of keys) key.destroy();
      throw cause;
    }
    return keys;
  }

  async prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    return parseProof(await this.#sealAndProve(proverRequestBody(inputs), operationOptions(context)));
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    return parseProof(
      await this.#sealAndProve(mergeProverRequestBody(inputs), operationOptions(context)),
    );
  }

  /**
   * Has the enclave seal the completed request to the attested prover and
   * posts it. One attestation serves every proof within the policy's
   * `max_age_secs`. A cached attestation or policy file the enclave refuses
   * is fetched again once; a prover that moved to a new key is attested
   * again under a freshly downloaded policy and the request sealed once more.
   */
  async #sealAndProve(request: ProverRequest, options: OperationOptions): Promise<unknown> {
    let fresh = false;
    for (let attempt = 0; ; attempt += 1) {
      const policy = await this.#policy.current(options.signal);
      const attested = await this.#attestation(policy, fresh, options.signal);
      let sealed;
      try {
        sealed = await this.#client.prove(
          this.#connection,
          this.#sealedSeed,
          request,
          sealingFor(policy, attested, request),
          options,
        );
      } catch (error) {
        if (fresh || !isProverStage(error)) throw error;
        this.#forgetProver();
        fresh = true;
        continue;
      }
      const answer = await submitSealed(this.#prover, sealed, options.signal);
      if (answer.kind === "proof") return answer.body;
      this.#forgetProver();
      if (attempt > 0) throw new TvcError("ProverKeyLost");
      fresh = true;
    }
  }

  async #attestation(
    policy: HeldProverPolicy,
    fresh: boolean,
    signal?: AbortSignal,
  ): Promise<ProverAttestation> {
    const cached = this.#attested;
    if (
      !fresh &&
      cached &&
      Date.now() - cached.fetchedAtMs < attestationReuseMs(policy, cached.fetchedAtMs)
    ) {
      return cached;
    }
    const attested = await fetchAttestation(this.#prover, signal);
    this.#attested = attested;
    return attested;
  }

  /** The prover likely changed release: attest again under a new policy download. */
  #forgetProver(): void {
    this.#attested = undefined;
    this.#policy.invalidate();
  }

  /** Respect both the item ceiling and the executor's serialized byte budget. */
  async #batched<TItem, TAnswer>(
    items: readonly TItem[],
    call: (batch: readonly TItem[]) => Promise<readonly TAnswer[]>,
  ): Promise<readonly TAnswer[]> {
    const answers: TAnswer[] = [];
    const send = async (batch: readonly TItem[]): Promise<void> => {
      let answer: readonly TAnswer[];
      try {
        answer = await call(batch);
      } catch (error) {
        // RequestTooLarge is raised locally before signing or sending. A
        // single item that cannot fit must fail rather than retry forever.
        if (!(error instanceof TvcError) || error.code !== "RequestTooLarge" || batch.length < 2) {
          throw error;
        }
        const middle = Math.floor(batch.length / 2);
        await send(batch.slice(0, middle));
        await send(batch.slice(middle));
        return;
      }
      if (answer.length !== batch.length) throw new Error("BatchMismatch");
      answers.push(...answer);
    };
    for (let start = 0; start < items.length; start += MAX_ITEMS_PER_BATCH) {
      await send(items.slice(start, start + MAX_ITEMS_PER_BATCH));
    }
    return answers;
  }
}

/** The enclave refused the prover's policy or attestation. */
function isProverStage(error: unknown): boolean {
  return error instanceof TvcOperationError && error.stage === "Prover";
}
