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

import { encodeDecimalU64 } from "../protocol/decimal.js";
import { SprEmbeddedWalletError, SprEmbeddedWalletOperationError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type {
  SealedSeed,
  DecryptItem,
  DecryptLabel,
  DeriveItem,
  ProverRequest,
  ProverSealing,
  SealedProverRequest,
  TransactionKeyItem,
} from "../protocol/types.js";
import type { ShieldedIdentity, StoredWallet } from "./client.js";
import { shieldedAddressOf } from "./identity.js";
import { MAX_ITEMS_PER_BATCH, type OperationOptions } from "./operations.js";
import {
  fetchAttestation,
  sealingFor,
  submitSealed,
  type ProverAttestation,
  type SprEmbeddedWalletProver,
} from "./prover.js";
import { attestationReuseMs, type HeldProverPolicy } from "./prover-policy.js";

/**
 * The wallet's four key operations over the client's verified connection, on
 * the wire's terms. Each presents the sealed seed; the enclave cannot use it
 * for another wallet or past a Quorum key rotation.
 */
export type SprEmbeddedWalletEnclave = {
  /** Opens each ciphertext with the wallet's viewing key; one plaintext per item. */
  decrypt(
    sealedSeed: SealedSeed,
    items: readonly DecryptItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Derives nullifiers and merge values; one value per item. */
  derive(
    sealedSeed: SealedSeed,
    items: readonly DeriveItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Mints per-transaction viewing secrets; one per item. */
  transactionKeys(
    sealedSeed: SealedSeed,
    items: readonly TransactionKeyItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /**
   * Completes the prover request with the nullifier secret and seals it to the
   * prover `prover` attests; the client posts the sealed request.
   */
  prove(
    sealedSeed: SealedSeed,
    request: ProverRequest,
    prover: ProverSealing,
    options?: OperationOptions,
  ): Promise<SealedProverRequest>;
};

export type SprEmbeddedWalletKeysInput = {
  readonly enclave: SprEmbeddedWalletEnclave;
  readonly sealedSeed: SealedSeed;
  readonly identity: ShieldedIdentity;
  /** The attested prover proofs are sealed to and posted at, under its policy. */
  readonly prover: SprEmbeddedWalletProver;
};

const LABELS: Record<DecryptRequest["label"], DecryptLabel> = {
  transfer: "Transfer",
  ringDeposit: "RingDeposit",
};

/**
 * The SDK's cancellation and deadline, as one signal for the enclave call. Built
 * once per SDK request, so a deadline covers every batch the request splits into.
 */
export function operationOptions(context: RequestContext | undefined): OperationOptions {
  const signals: AbortSignal[] = [];
  if (context?.signal) signals.push(context.signal);
  if (context?.timeoutMs !== undefined) signals.push(AbortSignal.timeout(context.timeoutMs));
  if (signals.length === 0) return {};
  return { signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals),
    ...(context?.timeoutMs === undefined ? {} : { timeoutMs: context.timeoutMs }) };
}

/** One SDK decrypt request on the wire's terms. */
export function decryptItem(request: DecryptRequest): DecryptItem {
  return {
    ciphertext: encodeLowerHex(request.ciphertext),
    viewing_public_key: encodeLowerHex(request.viewingPublicKey.toBytes()),
    transaction_viewing_public_key: encodeLowerHex(request.txViewingPublicKey.toBytes()),
    salt: encodeLowerHex(request.salt),
    slot_index: String(request.slotIndex),
    label: LABELS[request.label],
  };
}

/** Respect both the item ceiling and the executor's serialized byte budget. */
export async function batched<TItem, TAnswer>(
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
      if (!(error instanceof SprEmbeddedWalletError) || error.code !== "RequestTooLarge" || batch.length < 2) {
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

/**
 * The Zolana SDK's `WalletKeys`, answered by the enclave; `client.open`
 * returns it. Hand it to `syncWallet`, `buildTransferTransaction`, and every
 * other SDK flow in place of `LocalKeys`: each SDK request becomes one enclave
 * operation per batch. A proof's witness is completed with the nullifier
 * secret inside the enclave and sealed there to an attested prover; this
 * client posts the sealed request and never sees the secret. Nothing here
 * signs; the application's Solana signer does.
 */
export interface SprEmbeddedWalletKeys extends WalletKeys {
  /** What to persist and hand to `open` next time. */
  readonly stored: Required<StoredWallet>;
}

/** `SprEmbeddedWalletKeys` over a client's enclave operations and prover. */
export class EnclaveKeys implements SprEmbeddedWalletKeys {
  readonly stored: Required<StoredWallet>;
  readonly #enclave: SprEmbeddedWalletEnclave;
  readonly #sealedSeed: SealedSeed;
  readonly #address: ShieldedAddress;
  readonly #prover: SprEmbeddedWalletProver;
  #attested: ProverAttestation | undefined;

  constructor(input: SprEmbeddedWalletKeysInput) {
    this.#enclave = input.enclave;
    this.#sealedSeed = input.sealedSeed;
    this.#address = shieldedAddressOf(input.identity);
    this.#prover = input.prover;
    this.stored = Object.freeze({ identity: Object.freeze({ ...input.identity }), sealedSeed: input.sealedSeed });
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
    const plaintexts = await batched(
      requests.map(decryptItem),
      (items) => this.#enclave.decrypt(this.#sealedSeed, items, options),
    );
    return plaintexts.map(decodeLowerHex);
  }

  async derive(
    requests: readonly DeriveRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]> {
    const options = operationOptions(context);
    const values = await batched(
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
      (items) => this.#enclave.derive(this.#sealedSeed, items, options),
    );
    return values.map((value) => decodeLowerHex(value) as Bytes32);
  }

  async transactionKeys(
    requests: readonly TransactionKeyRequest[],
    context?: RequestContext,
  ): Promise<readonly ViewingKey[]> {
    const options = operationOptions(context);
    const secrets = await batched(
      requests.map(
        (request): TransactionKeyItem => ({
          viewing_public_key: encodeLowerHex(request.viewingPublicKey.toBytes()),
          first_nullifier: encodeLowerHex(request.firstNullifier),
        }),
      ),
      (items) => this.#enclave.transactionKeys(this.#sealedSeed, items, options),
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
      const policy = await this.#prover.policy.current(options.signal);
      const attested = await this.#attestation(policy, fresh, options.signal);
      let sealed;
      try {
        sealed = await this.#enclave.prove(
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
      if (attempt > 0) throw new SprEmbeddedWalletError("ProverKeyLost");
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
    this.#prover.policy.invalidate();
  }
}

/** The enclave refused the prover's policy or attestation. */
function isProverStage(error: unknown): boolean {
  return error instanceof SprEmbeddedWalletOperationError && error.stage === "Prover";
}
