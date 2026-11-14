/**
 * Clients for tests and local deployments, and `verifyLiveReplica` for the
 * release tooling.
 *
 * `createTestSprEmbeddedWallet` verifies an enclave exactly as `createSprEmbeddedWallet` does,
 * against a release and backend the caller names. `createLocalSprEmbeddedWallet` is
 * the explicitly unsafe local testkit: it preserves the encrypted operation
 * protocol and all response binding checks, but replaces Nitro and Turnkey
 * evidence with pinned local process keys. It accepts loopback HTTP only and
 * must never be used for funds.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import localTestkit from "./local-testkit.json";

import { createLocalSprEmbeddedWalletSession } from "./client/local-session.js";
import type { SprEmbeddedWalletBackend } from "./client/backend.js";
import type { SprRequestSigner } from "./client/operation-executor.js";
import type { SprEmbeddedWalletTransport } from "./client/transport.js";
import { decryptionServiceFromSession, type DecryptionService } from "./decryption-service/client.js";
import { SERVICE_PROOF_TYPE } from "./decryption-service/protocol.js";
import { createSprRequestSigner } from "./platform/signer.js";
import {
  clientKeyIdFor,
  descriptorDigest,
} from "./protocol/digest.js";
import { signWalletGrant } from "./protocol/grant.js";
import { API_VERSION } from "./protocol/constants.js";
import { encodeDecimalU64 } from "./protocol/decimal.js";
import { decodeLowerHex, encodeLowerHex } from "./protocol/hex.js";
import { requireNetwork } from "./protocol/network.js";
import type { Network, OperationKind, WalletDescriptor } from "./protocol/types.js";
import {
  clientFromSession,
  clientKeysOf,
  createClient,
  proverFor,
  turnkeyServicePublicKey,
  type TestSprEmbeddedWalletConfig,
  type SprEmbeddedWallet,
} from "./wallet/client.js";
import type { SprEmbeddedWalletClientKeys } from "./wallet/client-keys.js";
import type { SprEmbeddedWalletProverConfig } from "./wallet/prover.js";
import { SprEmbeddedWalletProverPolicy } from "./wallet/prover-policy.js";
import type { SprEmbeddedWalletTurnkey, SprEmbeddedWalletTurnkeyWalletAccount } from "./wallet/turnkey.js";

export type {
  BootProofResolver,
  EnclaveBackend,
  GatewayBackend,
  ResolveBootProofInput,
  SprEmbeddedWalletBackend,
} from "./client/backend.js";
export type { SignTvcRequestInput, SprRequestSigner } from "./client/operation-executor.js";
export { verifyLiveReplica, type VerifyLiveReplicaInput } from "./client/connection.js";
export { createSprRequestSigner, type SprRequestKey } from "./platform/signer.js";
export type { ReleaseTrust } from "./protocol/releases.js";
export type { QosIdentityPcrs } from "./verify/index.js";
export type { TestSprEmbeddedWalletConfig, TestSprEmbeddedWalletKey } from "./wallet/client.js";
export type { SprEmbeddedWalletProverConfig } from "./wallet/prover.js";

const te = new TextEncoder();
if (localTestkit.version !== 1) throw new Error("UnsupportedLocalTestkitFixture");
const LOCAL_PROVISIONING_SECRET = decodeLowerHex(localTestkit.provisioningPrivateKeyHex);
const LOCAL_CLIENT_SECRET = decodeLowerHex(localTestkit.clientPrivateKeyHex);
const LOCAL_GRANT_SECRET = decodeLowerHex(localTestkit.grantPrivateKeyHex);
const LOCAL_GRANT_LIFETIME_MS = 900_000n;
/** The testkit signs its own descriptor for a day, as a gateway does. */
const LOCAL_DESCRIPTOR_LIFETIME_MS = 86_400_000n;
const digestLabel = (label: string) => encodeLowerHex(sha256(te.encode(label)));
const LOCAL_OPERATIONS = localTestkit.operations as readonly OperationKind[];
/** What a testkit client pins in place of an attestation, whichever application the testkit runs. */
const LOCAL_RELEASE = {
  expectedReleaseId: localTestkit.releaseId,
  expectedSecurityDomainId: digestLabel(localTestkit.securityDomainLabel),
  expectedManifestDigest: digestLabel(localTestkit.manifestLabel),
  expectedExecutableDigest: digestLabel(localTestkit.executableLabel),
  expectedQuorumKeyId: localTestkit.quorumKeyId,
  expectedQuorumPublicKey: localTestkit.quorumPublicKey,
  expectedEphemeralPublicKey: localTestkit.ephemeralPublicKey,
} as const;

export type LocalSprEmbeddedWalletConfig<Account extends SprEmbeddedWalletTurnkeyWalletAccount = SprEmbeddedWalletTurnkeyWalletAccount> = {
  /** The network the testkit was built for (`SPR_NETWORK`, devnet by default). */
  readonly network: Network;
  /**
   * The testkit enclave, or a tvc-gateway in front of it, over loopback HTTP.
   * Without a `walletGrant`, the testkit signs one for each request it sends
   * the enclave.
   */
  readonly backend: SprEmbeddedWalletBackend;
  /**
   * The testkit's stand-in prover (`localProverConfig`), or with
   * `--live-prover` a TEE prover of the network under its policy. Defaults to
   * `/v1/spr` beside the backend's endpoint.
   */
  readonly prover?: SprEmbeddedWalletProverConfig;
  readonly nowMs?: () => bigint;
  readonly transport?: SprEmbeddedWalletTransport;
} & (
  | {
      /** The wallet the testkit holds; the testkit client key signs. */
      readonly solanaAddress: string;
      /**
       * A descriptor issued elsewhere, such as by a tvc-gateway holding the
       * testkit's provisioning key. It must grant the testkit client key and
       * name `solanaAddress`. Absent, the testkit signs its own.
       */
      readonly descriptor?: WalletDescriptor;
    }
  | {
      /**
       * A Turnkey session in place of the testkit client key, enrolled through
       * the tvc-gateway `backend` names, as `createSprEmbeddedWallet` does.
       */
      readonly turnkey: SprEmbeddedWalletTurnkey<Account>;
      readonly solanaAddress?: string;
    }
);

function localDescriptor(network: Network, solanaAddress: string, nowMs: bigint): WalletDescriptor {
  const clientPublic = p256.getPublicKey(LOCAL_CLIENT_SECRET, false);
  const unsigned = {
    version: API_VERSION,
    security_domain_id: digestLabel(localTestkit.securityDomainLabel),
    network,
    turnkey_organization_id: localTestkit.organizationId,
    turnkey_wallet_id: localTestkit.walletId,
    address: solanaAddress,
    allowed_clients: [
      {
        client_public_key: encodeLowerHex(clientPublic),
        allowed_operations: [...LOCAL_OPERATIONS],
      },
    ],
    expires_at_ms: encodeDecimalU64(nowMs + LOCAL_DESCRIPTOR_LIFETIME_MS),
    provisioning_signature: "",
  } satisfies WalletDescriptor;
  const signature = p256.sign(
    descriptorDigest(unsigned),
    LOCAL_PROVISIONING_SECRET,
    { lowS: true, prehash: false },
  );
  return Object.freeze({
    ...unsigned,
    provisioning_signature: encodeLowerHex(signature.toCompactRawBytes()),
  });
}

/**
 * A client of `config.backend` verified against `config.release`, or the
 * package's pin for `config.network`, with every check `createSprEmbeddedWallet`
 * makes: for a test deployment, or to reach an enclave without a gateway.
 */
export function createTestSprEmbeddedWallet<Account extends SprEmbeddedWalletTurnkeyWalletAccount>(
  config: TestSprEmbeddedWalletConfig<Account>,
): SprEmbeddedWallet {
  return createClient(config);
}

/** The unattested testkit's client, for the network the testkit was built for. */
export function createLocalSprEmbeddedWallet<Account extends SprEmbeddedWalletTurnkeyWalletAccount>(
  config: LocalSprEmbeddedWalletConfig<Account>,
): SprEmbeddedWallet {
  const network = requireNetwork(config.network);
  let fixed: { readonly descriptor: WalletDescriptor; readonly signer: SprRequestSigner } | undefined;
  let keys: SprEmbeddedWalletClientKeys;
  if ("turnkey" in config) {
    keys = clientKeysOf(config, { network, backend: config.backend, transport: config.transport, nowMs: config.nowMs });
  } else {
    const nowMs = config.nowMs?.() ?? BigInt(Date.now());
    fixed = {
      descriptor: config.descriptor ?? localDescriptor(network, config.solanaAddress, nowMs),
      signer: localSigner(),
    };
    keys = clientKeysOf(fixed, { network, backend: config.backend });
  }
  const backend: SprEmbeddedWalletBackend =
    config.backend.kind === "enclave" && !config.backend.walletGrant && fixed
      ? {
          ...config.backend,
          walletGrant: () => Promise.resolve(signWalletGrant({
            descriptor: fixed.descriptor,
            clientKeyId: fixed.signer.clientKeyId,
            projectId: "local-testkit",
            issuedAtMs: config.nowMs?.() ?? BigInt(Date.now()),
            lifetimeMs: LOCAL_GRANT_LIFETIME_MS,
          }, LOCAL_GRANT_SECRET)),
        }
      : config.backend;
  return clientFromSession(
    createLocalSprEmbeddedWalletSession({
      network,
      backend,
      ...LOCAL_RELEASE,
      expectedOperations: LOCAL_OPERATIONS,
      ...(config.nowMs === undefined ? {} : { nowMs: config.nowMs }),
      ...(config.transport === undefined ? {} : { transport: config.transport }),
    }),
    {
      network,
      servicePublicKey: turnkeyServicePublicKey(localTestkit.quorumPublicKey),
      keys,
      prover: proverFor(network, backend.endpoint, config.prover, config.transport),
    },
  );
}

/** The unattested local decryption service, `spr-tvc-decryption-service-local`, over loopback HTTP. */
export function createLocalDecryptionService(config: {
  /** The network the testkit was built for (`SPR_NETWORK`, devnet by default). */
  readonly network: Network;
  /**
   * The testkit enclave, or a tvc-gateway's `/v1/decryption` in front of it,
   * over loopback HTTP.
   */
  readonly endpoint: URL;
  /**
   * When set, `endpoint` is a gateway that returns Boot Proofs beside answers
   * (`decryptionService: true`). Defaults to a direct enclave.
   */
  readonly gateway?: true;
  readonly transport?: SprEmbeddedWalletTransport;
}): DecryptionService {
  const backend: SprEmbeddedWalletBackend = config.gateway
    ? { kind: "gateway", endpoint: config.endpoint, decryptionService: true }
    : { kind: "enclave", endpoint: config.endpoint };
  return decryptionServiceFromSession(createLocalSprEmbeddedWalletSession({
    network: requireNetwork(config.network),
    backend,
    ...LOCAL_RELEASE,
    expectedOperations: ["ServicePublicKeys", "ServiceDecrypt"],
    expectedProofType: SERVICE_PROOF_TYPE,
    ...(config.transport === undefined ? {} : { transport: config.transport }),
  }));
}

/** The testkit client key's signer. */
function localSigner() {
  const clientPublic = p256.getPublicKey(LOCAL_CLIENT_SECRET, false);
  return createSprRequestSigner({
    clientKeyId: clientKeyIdFor(clientPublic),
    async sign(message: string) {
      return p256
        .sign(sha256(te.encode(message)), LOCAL_CLIENT_SECRET, { lowS: true, prehash: false })
        .toCompactRawBytes();
    },
  });
}

/**
 * The testkit's stand-in attested prover (`spr-tvc-privacy-wallet-local
 * --prover-tee-port`), with the policy file it publishes. The local enclave
 * trusts its fixture root and the testkit's policy signer; nothing else does.
 */
export function localProverConfig(url: string, transport?: SprEmbeddedWalletTransport): SprEmbeddedWalletProverConfig {
  const base = new URL(url);
  if (base.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname)) {
    throw new Error("LocalProverRequiresLoopback");
  }
  const policy = new SprEmbeddedWalletProverPolicy(new URL("/local/prover-policy", base), transport);
  return { url, policy, ...(transport ? { transport } : {}) };
}
