import { awaitWithSignal } from "./request.js";
import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public, qosEncrypt } from "../crypto/qos.js";
import {
  API_VERSION,
  QOS_P256_PUBLIC_LEN,
  TVC_APP_PROOF_KEYS,
  TVC_APP_PROOF_SCHEME,
  TVC_QOS_PING_PROOF_TYPE,
} from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import type { ReleaseTrust } from "../protocol/releases.js";
import { SERVICE_INFO_KEYS, type Network, type ServiceInfo } from "../protocol/types.js";
import { createDefaultTransport, type TvcTransport } from "./transport.js";
import { verifyBootProof } from "../verify/index.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "../verify/release-policy.js";
import { fetchSession, lookupBootProof, type TvcBackend } from "./backend.js";
import { assertExactObjectKeys } from "./http.js";
import { requireCurrentReleasePolicy } from "./operation-executor.js";
import type { TvcTrustVerifier } from "./trust.js";

const PING_RESPONSE_KEYS = ["version", "tvc_app_proof"] as const;

type QosPingResponse = {
  version: number;
  tvc_app_proof: {
    scheme: string;
    public_key: string;
    proof_payload: string;
    signature: string;
  };
};

export type TvcConnectionConfig = {
  /** The network the enclave serves; the release policy must name it. */
  network: Network;
  /** Where the client reaches the enclave. */
  backend: TvcBackend;
  /** The release the enclave is verified against. */
  release: ReleaseTrust;
  /**
   * Verifier clock. A function, not an instant: a fixed value would freeze
   * request timestamps and certificate-chain validation for the client's
   * whole life.
   */
  nowMs?: () => bigint;
  transport?: TvcTransport;
  /** Total deadline for each verification or operation, including proof lookup. Defaults to two minutes. */
  requestTimeoutMs?: number;
};

const verifiedConnectionBrand: unique symbol = Symbol("VerifiedConnection");

export type VerifiedConnection = {
  readonly [verifiedConnectionBrand]: true;
  readonly releaseId: string;
  readonly network: Network;
};

export type ConnectedTvcRuntime = {
  readonly connection: VerifiedConnection;
  readonly backend: TvcBackend;
  readonly info: ServiceInfo;
  readonly transport: TvcTransport;
  readonly releasePolicyValidFromMs: bigint;
  readonly releasePolicyExpiresAtMs: bigint;
  readonly nowMs: () => bigint;
  readonly trustVerifier: TvcTrustVerifier;
  readonly requestTimeoutMs?: number;
};

export function createVerifiedConnection(releaseId: string, network: Network): VerifiedConnection {
  return Object.freeze({
    [verifiedConnectionBrand]: true as const,
    releaseId,
    network,
  });
}

export function parseServiceInfo(text: string): ServiceInfo {
  return parseStrictJson<ServiceInfo>(text, SERVICE_INFO_KEYS);
}

function requireQosPublicKey(value: string): Uint8Array {
  const bytes = decodeLowerHex(value);
  if (bytes.length !== QOS_P256_PUBLIC_LEN) throw new TvcError("InvalidPublicKey");
  return bytes;
}

/** A random challenge encrypted to the quorum key, and the payload the enclave must sign. */
export type QosPingChallenge = { readonly body: string; readonly payload: string };

export function qosPingChallenge(quorumPublicKey: string): QosPingChallenge {
  const quorumPublic = parseQosP256Public(requireQosPublicKey(quorumPublicKey));
  const payload = canonicalizeJsonValue({
    type: TVC_QOS_PING_PROOF_TYPE,
    version: API_VERSION,
    challenge: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
  });
  const body = canonicalizeJsonValue({
    version: API_VERSION,
    encrypted_challenge: encodeLowerHex(
      qosEncrypt(quorumPublic.encryption, new TextEncoder().encode(payload)),
    ),
  });
  return { body, payload };
}

export function verifyQosPingAnswer(text: string, challenge: QosPingChallenge): TurnkeyAppProofWire {
  const parsed = parseStrictJson<QosPingResponse>(text, PING_RESPONSE_KEYS);
  if (parsed.version !== API_VERSION) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(parsed.tvc_app_proof, TVC_APP_PROOF_KEYS, "TurnkeyEvidenceInvalid");
  const proof = parsed.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || proof.proof_payload !== challenge.payload) {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  // `proof.public_key` is self-asserted here and carries no weight until
  // verifyBootProof ties it to a pinned-PCR Nitro attestation. Discovery's
  // own `ephemeral_public_key` is never used as a verification input: /v1/info
  // and /v1/ping may be served by different healthy replicas, so it is an
  // advertisement.
  verifyP256Message(
    parseQosP256Public(requireQosPublicKey(proof.public_key)).signing,
    new TextEncoder().encode(proof.proof_payload),
    decodeLowerHex(proof.signature),
  );
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: proof.public_key,
    proofPayload: proof.proof_payload,
    signature: proof.signature,
  };
}

export async function connectAndVerifyTvc(
  config: TvcConnectionConfig,
  signal?: AbortSignal,
): Promise<ConnectedTvcRuntime> {
  signal?.throwIfAborted();
  const nowMs = config.nowMs ?? (() => BigInt(Date.now()));
  const { backend, network, release } = config;
  const { releasePolicy, qosIdentityPcrs } = release;
  verifySignedReleasePolicy(releasePolicy, release.releaseAuthorities, network, nowMs());
  const transport = config.transport ?? createDefaultTransport();

  const verifyReplica = async (
    appProof: TurnkeyAppProofWire,
    bootProof: TurnkeyBootProofWire | undefined,
    verificationNow: bigint,
    verifySignal?: AbortSignal,
  ) => awaitWithSignal(verifyBootProof({
    appProof,
    bootProof: bootProof ?? await lookupBootProof(backend, appProof, verifySignal),
    allowedManifestSha256: releasePolicy.policy.acceptedManifestDigests,
    expectedPcrs: qosIdentityPcrs,
    nowMs: verificationNow,
  }), verifySignal);

  const challenge = qosPingChallenge(releasePolicy.policy.quorumPublicKey);
  const session = await fetchSession(backend, challenge.body, transport, signal);
  const info = parseServiceInfo(session.infoText);
  bindDiscoveryToPolicy(info, releasePolicy);
  const appProof = verifyQosPingAnswer(session.pingText, challenge);
  await verifyReplica(appProof, session.bootProof, nowMs(), signal);

  const releasePolicyValidFromMs = BigInt(releasePolicy.policy.validFromMs);
  const releasePolicyExpiresAtMs = BigInt(releasePolicy.policy.expiresAtMs);
  const trustVerifier: TvcTrustVerifier = Object.freeze({
    async verifyOperationAppProof(operationAppProof, operationSignal, operationBootProof) {
      operationSignal?.throwIfAborted();
      const verificationNow = nowMs();
      requireCurrentReleasePolicy(
        { releasePolicyValidFromMs, releasePolicyExpiresAtMs },
        verificationNow,
      );
      await verifyReplica(operationAppProof, operationBootProof, verificationNow, operationSignal);
    },
  });

  return {
    connection: createVerifiedConnection(info.release_id, network),
    backend,
    info,
    transport,
    releasePolicyValidFromMs,
    releasePolicyExpiresAtMs,
    nowMs,
    trustVerifier,
    ...(config.requestTimeoutMs === undefined ? {} : { requestTimeoutMs: config.requestTimeoutMs }),
  };
}
