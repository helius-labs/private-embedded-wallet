import {
  API_VERSION,
  TVC_APP_PROOF_TYPE,
} from "../protocol/constants.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";
import type { Network, OperationKind } from "../protocol/types.js";
import { fetchSession, type SprEmbeddedWalletBackend } from "./backend.js";
import {
  parseServiceInfo,
  qosPingChallenge,
  verifyQosPingAnswer,
  type ConnectedTvcRuntime,
} from "./connection.js";
import { createDefaultTransport, type SprEmbeddedWalletTransport } from "./transport.js";

export type LocalUnattestedConnectionConfig = {
  /** The network the testkit was built for. */
  readonly network: Network;
  readonly backend: SprEmbeddedWalletBackend;
  readonly expectedReleaseId: string;
  readonly expectedSecurityDomainId: string;
  readonly expectedManifestDigest: string;
  readonly expectedExecutableDigest: string;
  readonly expectedQuorumKeyId: string;
  readonly expectedQuorumPublicKey: string;
  readonly expectedEphemeralPublicKey: string;
  readonly expectedOperations: readonly OperationKind[];
  /** The privacy wallet's by default. */
  readonly expectedProofType?: string;
  readonly nowMs?: () => bigint;
  readonly transport?: SprEmbeddedWalletTransport;
};

/** Internal connection path reachable only from the package's testkit entry. */
export async function connectLocalUnattestedTvc(
  config: LocalUnattestedConnectionConfig,
  signal?: AbortSignal,
): Promise<ConnectedTvcRuntime> {
  const { endpoint } = config.backend;
  if (
    endpoint.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname)
  ) {
    throw new SprEmbeddedWalletError("DiscoveryUntrusted", "local testkit must use a loopback HTTP endpoint");
  }
  const transport = config.transport ?? createDefaultTransport();
  const challenge = qosPingChallenge(config.expectedQuorumPublicKey);
  const session = await fetchSession(config.backend, challenge.body, transport, signal);
  const info = parseServiceInfo(session.infoText);
  if (
    info.version !== API_VERSION ||
    info.network !== config.network ||
    info.release_id !== config.expectedReleaseId ||
    info.security_domain_id !== config.expectedSecurityDomainId ||
    info.manifest_digest !== config.expectedManifestDigest ||
    info.executable_digest !== config.expectedExecutableDigest ||
    info.quorum_key_id !== config.expectedQuorumKeyId ||
    info.quorum_key_epoch !== "1" ||
    info.proof_type !== (config.expectedProofType ?? TVC_APP_PROOF_TYPE) ||
    info.quorum_public_key !== config.expectedQuorumPublicKey ||
    info.ephemeral_public_key !== config.expectedEphemeralPublicKey ||
    info.supported_operations.length !== config.expectedOperations.length ||
    config.expectedOperations.some(
      (operation, index) => info.supported_operations[index] !== operation,
    )
  ) {
    throw new SprEmbeddedWalletError("DiscoveryUntrusted", "local testkit identity does not match");
  }

  const appProof = verifyQosPingAnswer(session.pingText, challenge);
  if (appProof.publicKey !== config.expectedEphemeralPublicKey) {
    throw new SprEmbeddedWalletError("DiscoveryUntrusted", "local ping used another key");
  }
  const nowMs = config.nowMs ?? (() => BigInt(Date.now()));
  return {
    backend: config.backend,
    info,
    transport,
    releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 0xffff_ffff_ffff_ffffn,
    nowMs,
    trustVerifier: Object.freeze({
      async verifyOperationAppProof(proof) {
        if (proof.publicKey !== config.expectedEphemeralPublicKey) {
          throw new SprEmbeddedWalletError("TurnkeyEvidenceInvalid");
        }
      },
    }),
  };
}
