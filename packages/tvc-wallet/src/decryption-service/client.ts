import {
  NullifierKey,
  ShieldedAddress,
  ShieldedPublicKey,
  ViewingKey,
  type Bytes32,
  type DecryptRequest,
  type DeriveRequest,
  type ProofService,
  type RequestContext,
  type WalletKeys,
} from "@heliuslabs/spr";
import { LocalKeys } from "@heliuslabs/spr/client";
import { X25519PublicKey, type Bytes31 } from "@heliuslabs/spr/keypair";
import type { TransactionKeyRequest } from "@heliuslabs/spr/transaction";
import { p256 } from "@noble/curves/p256";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  createSignableMessage,
  getAddressEncoder,
  type Address,
  type MessagePartialSigner,
} from "@solana/kit";

import {
  sendDecryptionOperation,
  type BootProofResolver,
  type SprEmbeddedWalletBackend,
} from "../client/backend.js";
import type { ConnectedTvcRuntime } from "../client/connection.js";
import {
  checkSignedRequestSize,
  requireCurrentReleasePolicy,
  sealedExchange,
} from "../client/operation-executor.js";
import { requestScope, type SprEmbeddedWalletRequestOptions } from "../client/request.js";
import { createSprEmbeddedWalletSession, type SprEmbeddedWalletSession } from "../client/session.js";
import type { SprEmbeddedWalletTransport } from "../client/transport.js";
import { API_VERSION } from "../protocol/constants.js";
import { SprEmbeddedWalletError, SprEmbeddedWalletHttpError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import { requireNetwork } from "../protocol/network.js";
import { pinnedReleases, releaseFor, type ReleaseTrust } from "../protocol/releases.js";
import type { DecryptItem, Network } from "../protocol/types.js";
import { batched, decryptItem, operationOptions } from "../wallet/keys.js";
import { checkHexList } from "../wallet/operations.js";
import {
  SERVICE_PROOF_TYPE,
  decryptMessage,
  serviceRequestDigest,
  type ServiceOperation,
  type ServiceRequest,
  type ServiceResult,
} from "./protocol.js";
import devnet from "./releases/devnet.json";
import mainnet from "./releases/mainnet.json";

/** The live decryption-service release of each network that has one. */
export const DECRYPTION_SERVICE_RELEASES = pinnedReleases({ devnet, mainnet });

/** Label of the key a wallet mints its per-transaction keys from, under the service keys. */
const TRANSACTION_KEY_LABEL = "TSPP/decryption-service/tx_key/v1";
const ED25519_SIGNATURE_BYTES = 64;
const OPERATION_KINDS = { PublicKeys: "ServicePublicKeys", Decrypt: "ServiceDecrypt" } as const;
const RESULT_KEYS = {
  PublicKeys: ["type", "viewing_public_key", "nullifier_public_key"],
  Decrypt: ["type", "nullifier_secret", "plaintexts"],
} as const;

const te = new TextEncoder();
const addressEncoder = getAddressEncoder();

export type DecryptionServiceConfig = {
  readonly network: Network;
  /**
   * The enclave's public ingress, or a tvc-gateway's `/v1/decryption` (with any
   * query such as gatekeeper's `api-key`). Without `resolveBootProof` the
   * client treats `endpoint` as a gateway and reads Boot Proofs beside session
   * and operation answers.
   */
  readonly endpoint: URL;
  /**
   * Fetches a replica's Boot Proof when talking to the enclave directly, such
   * as with an authenticated Turnkey session. Omit for a gateway endpoint.
   */
  readonly resolveBootProof?: BootProofResolver;
  /** The release to verify against; the package's pin for `network` by default. */
  readonly release?: ReleaseTrust;
  readonly nowMs?: () => bigint;
  readonly transport?: SprEmbeddedWalletTransport;
  readonly requestTimeoutMs?: number;
};

/** The SDK's `WalletKeys` for an address under its service keys. */
export interface DecryptionServiceKeys extends WalletKeys {
  destroy(): void;
}

export type DecryptionService = {
  /** The shielded address a sender pays `owner` at before `owner` registers a wallet. */
  address(owner: Address, options?: SprEmbeddedWalletRequestOptions): Promise<ShieldedAddress>;
  /**
   * The keys of that address, for its owner. `owner` signs once here and once
   * for every batch of outputs a sync opens.
   */
  open(
    owner: MessagePartialSigner,
    proofs: ProofService,
    options?: SprEmbeddedWalletRequestOptions,
  ): Promise<DecryptionServiceKeys>;
};

type ResultFor<TOperation extends ServiceOperation> = Extract<
  ServiceResult,
  { type: TOperation["type"] }
>;

/** Opens `items` with the service viewing key; one hex plaintext per item. */
type Decrypt = (items: readonly DecryptItem[], context?: RequestContext) => Promise<readonly string[]>;

/** One request over the verified connection, signed by `owner` when it is a `Decrypt`. */
async function execute<TOperation extends ServiceOperation>(
  context: ConnectedTvcRuntime,
  operation: TOperation,
  owner: MessagePartialSigner | undefined,
  signal: AbortSignal,
): Promise<ResultFor<TOperation>> {
  const { info } = context;
  requireCurrentReleasePolicy(context, context.nowMs());
  const responseSecret = p256.utils.randomPrivateKey();
  let request: ServiceRequest = {
    version: API_VERSION,
    request_id: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
    target_release_id: info.release_id,
    target_manifest_digest: info.manifest_digest,
    target_executable_digest: info.executable_digest,
    quorum_key_id: info.quorum_key_id,
    quorum_key_epoch: info.quorum_key_epoch,
    client_response_public_key: encodeLowerHex(p256.getPublicKey(responseSecret, false)),
    operation,
  };
  const requestDigest = serviceRequestDigest(request);
  try {
    checkSignedRequestSize(context, request, {});
    if (operation.type === "Decrypt" && owner) {
      const message = decryptMessage(
        new Uint8Array(addressEncoder.encode(owner.address)),
        info.network,
        requestDigest,
      );
      const [signatures] = await owner.signMessages([createSignableMessage(message)]);
      const signature = signatures?.[owner.address];
      if (signature?.length !== ED25519_SIGNATURE_BYTES) {
        throw new SprEmbeddedWalletError("InvalidSignature");
      }
      request = { ...request, operation: { ...operation, signature: encodeLowerHex(signature) } };
    }
  } catch (error) {
    responseSecret.fill(0);
    throw error;
  }
  const { plaintext } = await sealedExchange(context, {
    request,
    requestDigest,
    responseSecret,
    operation: OPERATION_KINDS[operation.type],
    proofType: SERVICE_PROOF_TYPE,
    grant: {},
    send: (encrypted, maxAnswerBytes) =>
      sendDecryptionOperation(context.backend, encrypted, context.transport, maxAnswerBytes, signal),
  }, signal);
  const result = parseStrictJson<ServiceResult>(plaintext, RESULT_KEYS[operation.type]);
  if (result.type !== operation.type) throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
  return result as ResultFor<TOperation>;
}

/** The service keys' half of the SDK's `WalletKeys`; everything else is `local`. */
export class ServiceKeys implements DecryptionServiceKeys {
  readonly #address: ShieldedAddress;
  readonly #local: LocalKeys;
  readonly #transactionKey: X25519PublicKey;
  readonly #decrypt: Decrypt;

  constructor(
    address: ShieldedAddress,
    nullifierSecret: Bytes31,
    proofs: ProofService,
    decrypt: Decrypt,
  ) {
    // The service viewing secret stays in the enclave: transaction keys come from a key of the wallet's own.
    const nullifierKey = NullifierKey.fromSecret(nullifierSecret);
    const transactionKey = ViewingKey.fromBytes(
      hkdf(sha256, nullifierSecret, undefined, te.encode(TRANSACTION_KEY_LABEL), 32) as Bytes32,
    );
    try {
      this.#transactionKey = transactionKey.publicKey();
      this.#local = LocalKeys.fromKeys({
        address: ShieldedAddress.fromPublicKeys(
          address.signingPublicKey,
          address.nullifierPublicKey,
          this.#transactionKey,
        ),
        viewingKeys: [transactionKey],
        nullifierKey,
      }, proofs);
    } finally {
      nullifierKey.destroy();
      transactionKey.destroy();
    }
    this.#address = address;
    this.#decrypt = decrypt;
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
    const plaintexts = await batched(requests.map(decryptItem), (items) => this.#decrypt(items, context));
    return plaintexts.map(decodeLowerHex);
  }

  derive(requests: readonly DeriveRequest[]): Promise<readonly Bytes32[]> {
    return this.#local.derive(requests);
  }

  transactionKeys(requests: readonly TransactionKeyRequest[]): Promise<readonly ViewingKey[]> {
    return this.#local.transactionKeys(
      requests.map((request) => ({ ...request, viewingPublicKey: this.#transactionKey })),
    );
  }

  prove: LocalKeys["prove"] = (inputs, context) => this.#local.prove(inputs, context);
  proveMerge: LocalKeys["proveMerge"] = (inputs, context) => this.#local.proveMerge(inputs, context);
  proveIndexed: LocalKeys["proveIndexed"] = (request, context) => this.#local.proveIndexed(request, context);

  destroy(): void {
    this.#local.destroy();
  }
}

export function decryptionServiceFromSession(
  session: SprEmbeddedWalletSession,
  requestTimeoutMs?: number,
): DecryptionService {
  async function call<TOperation extends ServiceOperation>(
    operation: TOperation,
    owner: MessagePartialSigner | undefined,
    options?: SprEmbeddedWalletRequestOptions,
  ): Promise<ResultFor<TOperation>> {
    const scope = requestScope(options, requestTimeoutMs);
    try {
      const context = await session.context({ ...options, signal: scope.signal });
      try {
        return await execute(context, operation, owner, scope.signal);
      } catch (error) {
        // A refused or failed exchange may mean the release moved on.
        if (error instanceof SprEmbeddedWalletHttpError && error.status !== 429) session.forget(context);
        throw error;
      }
    } finally {
      scope.dispose();
    }
  }

  async function address(owner: Address, options?: SprEmbeddedWalletRequestOptions): Promise<ShieldedAddress> {
    const keys = await call({ type: "PublicKeys", address: owner }, undefined, options);
    return ShieldedAddress.fromPublicKeys(
      ShieldedPublicKey.fromEd25519(new Uint8Array(addressEncoder.encode(owner)) as Bytes32),
      requireHex(keys.nullifier_public_key, 32) as Bytes32,
      X25519PublicKey.fromBytes(requireHex(keys.viewing_public_key, 33)),
    );
  }

  async function decrypt(
    owner: MessagePartialSigner,
    items: readonly DecryptItem[],
    options?: SprEmbeddedWalletRequestOptions,
  ) {
    const result = await call(
      { type: "Decrypt", signer: owner.address, signature: "00".repeat(ED25519_SIGNATURE_BYTES), items },
      owner,
      options,
    );
    checkHexList(result.plaintexts, items.length);
    return result;
  }

  return {
    address,
    async open(owner, proofs, options) {
      const shielded = await address(owner.address, options);
      // A decryption of nothing returns the nullifier secret alone.
      const nullifierSecret = requireHex((await decrypt(owner, [], options)).nullifier_secret, 31) as Bytes31;
      try {
        return new ServiceKeys(shielded, nullifierSecret, proofs, async (items, context) =>
          (await decrypt(owner, items, operationOptions(context))).plaintexts);
      } finally {
        nullifierSecret.fill(0);
      }
    },
  };
}

/** Direct enclave or gateway backend for `createDecryptionService`. */
function decryptionBackend(
  endpoint: URL,
  resolveBootProof: BootProofResolver | undefined,
): SprEmbeddedWalletBackend {
  if (resolveBootProof) {
    return { kind: "enclave", endpoint, resolveBootProof };
  }
  return { kind: "gateway", endpoint, decryptionService: true };
}

/** A client of the decryption service at `config.endpoint`, verified against its release. */
export function createDecryptionService(config: DecryptionServiceConfig): DecryptionService {
  const network = requireNetwork(config.network);
  const { endpoint, resolveBootProof, nowMs, transport, requestTimeoutMs } = config;
  return decryptionServiceFromSession(
    createSprEmbeddedWalletSession({
      network,
      backend: decryptionBackend(endpoint, resolveBootProof),
      release: config.release ?? releaseFor(network, DECRYPTION_SERVICE_RELEASES),
      proofType: SERVICE_PROOF_TYPE,
      ...(nowMs === undefined ? {} : { nowMs }),
      ...(transport === undefined ? {} : { transport }),
      ...(requestTimeoutMs === undefined ? {} : { requestTimeoutMs }),
    }),
    requestTimeoutMs,
  );
}
