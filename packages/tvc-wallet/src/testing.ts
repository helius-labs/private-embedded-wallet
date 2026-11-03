/**
 * Explicitly unsafe local TVC testkit.
 *
 * This entrypoint preserves the encrypted operation protocol and all response
 * binding checks, but replaces Nitro and Turnkey evidence with pinned local
 * process keys. It accepts loopback HTTP only and must never be used for funds.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import localTestkit from "./local-testkit.json";

import { createLocalTvcSession } from "./client/local-session.js";
import type { TvcBackend } from "./client/backend.js";
import type { TvcTransport } from "./client/transport.js";
import { createTvcOperationAuthorizer } from "./platform/authorizer.js";
import {
  clientKeyIdFor,
  descriptorDigest,
} from "./protocol/digest.js";
import { signWalletGrant } from "./protocol/grant.js";
import { decodeLowerHex, encodeLowerHex } from "./protocol/hex.js";
import type { OperationKind, WalletDescriptor } from "./protocol/types.js";
import { clientFromSession, type TvcClient } from "./wallet/client.js";
import type { TvcProverConfig } from "./wallet/prover.js";
import { TvcProverPolicy } from "./wallet/prover-policy.js";

const te = new TextEncoder();
if (localTestkit.version !== 1) throw new Error("UnsupportedLocalTestkitFixture");
const LOCAL_PROVISIONING_SECRET = decodeLowerHex(localTestkit.provisioningPrivateKeyHex);
const LOCAL_CLIENT_SECRET = decodeLowerHex(localTestkit.clientPrivateKeyHex);
const LOCAL_GRANT_SECRET = decodeLowerHex(localTestkit.grantPrivateKeyHex);
const LOCAL_GRANT_LIFETIME_MS = 900_000n;
const digestLabel = (label: string) => encodeLowerHex(sha256(te.encode(label)));
const LOCAL_OPERATIONS = localTestkit.operations as readonly OperationKind[];

export type LocalTvcClientConfig = {
  /**
   * The testkit enclave, or a tvc-gateway in front of it, over loopback HTTP.
   * Without a `walletGrant`, the testkit signs one for each request it sends
   * the enclave.
   */
  readonly backend: TvcBackend;
  readonly solanaAddress: string;
  readonly nowMs?: () => bigint;
  readonly transport?: TvcTransport;
  /**
   * A descriptor issued elsewhere, such as by a provisioning service holding
   * the testkit's provisioning key. It must grant the testkit client key and
   * name `solanaAddress`. Absent, the testkit signs its own.
   */
  readonly walletDescriptor?: WalletDescriptor;
};

function localDescriptor(solanaAddress: string): WalletDescriptor {
  const clientPublic = p256.getPublicKey(LOCAL_CLIENT_SECRET, false);
  const unsigned = {
    version: 1,
    security_domain_id: digestLabel(localTestkit.securityDomainLabel),
    environment: "development",
    turnkey_organization_id: localTestkit.organizationId,
    turnkey_wallet_id: localTestkit.walletId,
    address: solanaAddress,
    allowed_clients: [
      {
        client_public_key: encodeLowerHex(clientPublic),
        allowed_operations: [...LOCAL_OPERATIONS],
      },
    ],
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

export function createLocalTvcClient(config: LocalTvcClientConfig): TvcClient {
  const descriptor = config.walletDescriptor ?? localDescriptor(config.solanaAddress);
  const clientPublic = p256.getPublicKey(LOCAL_CLIENT_SECRET, false);
  const authorizer = createTvcOperationAuthorizer({
    clientKeyId: clientKeyIdFor(clientPublic),
    async sign(message: Uint8Array) {
      return p256
        .sign(sha256(message), LOCAL_CLIENT_SECRET, { lowS: true, prehash: false })
        .toCompactRawBytes();
    },
  });
  const localGrant = () => {
    const nowMs = config.nowMs?.() ?? BigInt(Date.now());
    return Promise.resolve(signWalletGrant({
      descriptor,
      clientKeyId: clientKeyIdFor(clientPublic),
      projectId: "local-testkit",
      issuedAtMs: nowMs,
      lifetimeMs: LOCAL_GRANT_LIFETIME_MS,
    }, LOCAL_GRANT_SECRET));
  };
  const backend: TvcBackend =
    config.backend.kind === "enclave" && !config.backend.walletGrant
      ? { ...config.backend, walletGrant: localGrant }
      : config.backend;
  return clientFromSession(
    createLocalTvcSession({
      backend,
      expectedReleaseId: localTestkit.releaseId,
      expectedSecurityDomainId: digestLabel(localTestkit.securityDomainLabel),
      expectedManifestDigest: digestLabel(localTestkit.manifestLabel),
      expectedExecutableDigest: digestLabel(localTestkit.executableLabel),
      expectedQuorumKeyId: localTestkit.quorumKeyId,
      expectedQuorumPublicKey: localTestkit.quorumPublicKey,
      expectedEphemeralPublicKey: localTestkit.ephemeralPublicKey,
      expectedOperations: LOCAL_OPERATIONS,
      ...(config.nowMs === undefined ? {} : { nowMs: config.nowMs }),
      ...(config.transport === undefined ? {} : { transport: config.transport }),
      operations: { walletDescriptor: descriptor, authorizer },
    }),
  );
}

/**
 * The testkit's stand-in attested prover (`zolana-tvc-privacy-wallet-local
 * --prover-tee-port`), with the policy file it publishes. The local enclave
 * trusts its fixture root and the testkit's policy signer; nothing else does.
 */
export function localProverConfig(url: string, transport?: TvcTransport): TvcProverConfig {
  const base = new URL(url);
  if (base.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname)) {
    throw new Error("LocalProverRequiresLoopback");
  }
  const policy = new TvcProverPolicy(new URL("/local/prover-policy", base), transport);
  return { url, policy, ...(transport ? { transport } : {}) };
}
