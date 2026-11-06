import { awaitWithSignal } from "./request.js";
import { p256 } from "@noble/curves/p256";
import { parseQosP256Public, qosDecrypt, qosEncrypt } from "../crypto/qos.js";
import { verifyP256Message, verifyP256Prehash } from "../crypto/p256.js";
import {
  clientKeyIdFor,
  clientAuthDigest,
  clientAuthMessage,
  requestDigest,
  resultDigest,
} from "../protocol/digest.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError } from "../protocol/error.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { canonicalizeJsonValue, isRfc8785 } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import {
  API_VERSION,
  AES_GCM_NONCE_LEN,
  AES_GCM_TAG_LEN,
  MAX_REQUEST_AGE_MS,
  QOS_P256_PUBLIC_LEN,
  RAW_P256_SIGNATURE_LEN,
  SEC1_UNCOMPRESSED_LEN,
  SHA256_LEN,
  TVC_APP_PROOF_KEYS,
  TVC_APP_PROOF_SCHEME,
  TVC_APP_PROOF_TYPE,
} from "../protocol/constants.js";
import type {
  Operation,
  OperationKind,
  OperationRequest,
  ServiceInfo,
  SealedSeed,
  WalletDescriptor,
  WalletGrant,
} from "../protocol/types.js";
import type { TvcTransport } from "./transport.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import {
  forwardedRequestBytes,
  requestGrant,
  sendOperation,
  type EncryptedRequestWire,
  type TvcBackend,
} from "./backend.js";
import { assertExactObjectKeys } from "./http.js";
import type { TvcTrustVerifier } from "./trust.js";

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const ENCRYPTED_RESPONSE_KEYS = [
  "version",
  "request_id",
  "encrypted_result",
  "tvc_app_proof",
] as const;
/** Room for the JSON envelope and App Proof around the hex ciphertext. */
const RESPONSE_ENVELOPE_SLACK = 65_536n;

const OPERATION_PROOF_KEYS = [
  "type",
  "version",
  "request_id",
  "request_digest",
  "result_digest",
  "operation",
  "sealed_seed_digest",
] as const;

type EncryptedResponse = {
  version: number;
  request_id: string;
  encrypted_result: string;
  tvc_app_proof: {
    scheme: string;
    public_key: string;
    proof_payload: string;
    signature: string;
  };
};

type OperationProofPayload = {
  type: string;
  version: number;
  request_id: string;
  request_digest: string;
  result_digest: string;
  operation: OperationKind;
  sealed_seed_digest: string;
};

export type AuthorizeTvcRequestInput = {
  readonly operation: Operation;
  readonly request: Readonly<OperationRequest>;
  readonly clientAuthDigest: Uint8Array;
  readonly clientAuthMessage: Uint8Array;
  readonly signal?: AbortSignal;
};

export type TvcOperationAuthorizer = {
  readonly clientKeyId: string;
  authorizeTvcRequest(input: AuthorizeTvcRequestInput): Promise<Uint8Array>;
};

export type OperationsConfig = {
  readonly walletDescriptor: WalletDescriptor;
  readonly authorizer: TvcOperationAuthorizer;
};

export type OperationExecutionContext = {
  readonly backend: TvcBackend;
  readonly info: ServiceInfo;
  readonly transport: TvcTransport;
  readonly operations: OperationsConfig;
  readonly releasePolicyValidFromMs: bigint;
  readonly releasePolicyExpiresAtMs: bigint;
  readonly nowMs: () => bigint;
  readonly trustVerifier: TvcTrustVerifier;
  readonly requestTimeoutMs?: number;
};

export function requireCurrentReleasePolicy(
  window: {
    readonly releasePolicyValidFromMs: bigint;
    readonly releasePolicyExpiresAtMs: bigint;
  },
  nowMs: bigint,
): void {
  if (nowMs < window.releasePolicyValidFromMs || nowMs > window.releasePolicyExpiresAtMs) {
    throw new TvcError("ExpiredRequest");
  }
}

function sealedSeedFields(sealedSeed?: SealedSeed) {
  if (!sealedSeed) {
    return {
      sealed_seed: null,
    };
  }
  requireHex(sealedSeed.sealedSeed);
  return {
    sealed_seed: sealedSeed.sealedSeed,
  };
}

function matchingGrant(
  descriptor: WalletDescriptor,
  clientKeyId: string,
  operation: OperationKind,
) {
  const grant = descriptor.allowed_clients.find(
    (candidate) => clientKeyIdFor(decodeLowerHex(candidate.client_public_key)) === clientKeyId,
  );
  if (!grant || !grant.allowed_operations.includes(operation)) {
    throw new TvcError("OperationNotAllowed");
  }
  return grant;
}

type RequestGrant = { readonly wallet_grant?: WalletGrant };

function encryptedRequest(
  info: ServiceInfo,
  ciphertext: string,
  grant: RequestGrant,
): EncryptedRequestWire {
  return {
    version: API_VERSION,
    quorum_key_id: info.quorum_key_id,
    quorum_key_epoch: info.quorum_key_epoch,
    ciphertext,
    ...grant,
  };
}

/** The size of the request the enclave receives, including anything the backend adds. */
function enclaveRequestBytes(context: OperationExecutionContext, request: EncryptedRequestWire): number {
  return te.encode(canonicalizeJsonValue(request)).length + forwardedRequestBytes(context.backend);
}

/** The advertised request ceiling covers the entire UTF-8 HTTP body. */
function checkRequestSize(info: ServiceInfo, bytes: number): void {
  if (BigInt(bytes) > BigInt(info.max_encrypted_request_bytes)) {
    throw new TvcError("RequestTooLarge");
  }
}

async function prepareRequest(
  context: OperationExecutionContext,
  operation: Operation,
  sealedSeed?: SealedSeed,
  signal?: AbortSignal,
): Promise<{ request: OperationRequest; responseSecret: Uint8Array; grant: RequestGrant }> {
  // A release that does not advertise the operation, or a descriptor that
  // does not grant it, is refused here rather than by a rejected request.
  signal?.throwIfAborted();
  const kind = operation.type;
  if (!context.info.supported_operations.includes(kind)) {
    throw new TvcError("OperationNotAllowed");
  }
  // The enclave refuses a descriptor for another network; say so before signing.
  if (context.operations.walletDescriptor.network !== context.info.network) {
    throw new TvcError("NetworkMismatch", "the wallet descriptor is for another network");
  }
  const grant = matchingGrant(
    context.operations.walletDescriptor,
    context.operations.authorizer.clientKeyId,
    kind,
  );
  const requestGrantFields = await requestGrant(context.backend, signal);
  const issuedAt = context.nowMs();
  requireCurrentReleasePolicy(context, issuedAt);
  const responseSecret = p256.utils.randomPrivateKey();
  try {
    const responsePublic = p256.getPublicKey(responseSecret, false);
    let request: OperationRequest = {
      version: API_VERSION,
      request_id: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
      issued_at_ms: encodeDecimalU64(issuedAt),
      expires_at_ms: encodeDecimalU64(issuedAt + MAX_REQUEST_AGE_MS),
      target_release_id: context.info.release_id,
      target_manifest_digest: context.info.manifest_digest,
      target_executable_digest: context.info.executable_digest,
      quorum_key_id: context.info.quorum_key_id,
      quorum_key_epoch: context.info.quorum_key_epoch,
      wallet_descriptor: context.operations.walletDescriptor,
      ...sealedSeedFields(sealedSeed),
      client_response_public_key: encodeLowerHex(responsePublic),
      operation,
      authorization: {
        client_key_id: context.operations.authorizer.clientKeyId,
        signature: "",
      },
    };
    // A raw P-256 signature has a fixed width. Account for it before asking the
    // authorizer to sign, so TvcKeys can split an oversized batch locally.
    const signedBytes = te.encode(canonicalizeJsonValue({
      ...request,
      authorization: { ...request.authorization, signature: "00".repeat(RAW_P256_SIGNATURE_LEN) },
    })).length;
    const ciphertextBytes = signedBytes + AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN + 4 + AES_GCM_TAG_LEN;
    checkRequestSize(
      context.info,
      enclaveRequestBytes(context, encryptedRequest(context.info, "", requestGrantFields)) + 2 * ciphertextBytes,
    );
    const requestDigestBytes = requestDigest(request);
    const digest = clientAuthDigest(requestDigestBytes);
    const signature = await awaitWithSignal(context.operations.authorizer.authorizeTvcRequest({
      operation,
      request,
      clientAuthDigest: digest.slice(),
      clientAuthMessage: clientAuthMessage(requestDigestBytes),
      ...(signal ? { signal } : {}),
    }), signal);
    verifyP256Prehash(requireHex(grant.client_public_key, SEC1_UNCOMPRESSED_LEN), digest, signature);
    request = {
      ...request,
      authorization: { ...request.authorization, signature: encodeLowerHex(signature) },
    };
    return { request, responseSecret, grant: requestGrantFields };
  } catch (error) {
    responseSecret.fill(0);
    throw error;
  }
}

function asAppProof(proof: EncryptedResponse["tvc_app_proof"]): TurnkeyAppProofWire {
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: proof.public_key,
    proofPayload: proof.proof_payload,
    signature: proof.signature,
  };
}

async function verifyOperationProof(
  context: OperationExecutionContext,
  request: OperationRequest,
  response: EncryptedResponse,
  bootProof: TurnkeyBootProofWire | undefined,
  signal?: AbortSignal,
): Promise<OperationProofPayload> {
  assertExactObjectKeys(response.tvc_app_proof, TVC_APP_PROOF_KEYS, "InvalidCanonicalJson");
  const proof = response.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || !isRfc8785(proof.proof_payload)) {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  const proofPublic = parseQosP256Public(requireHex(proof.public_key, QOS_P256_PUBLIC_LEN));
  verifyP256Message(
    proofPublic.signing,
    te.encode(proof.proof_payload),
    requireHex(proof.signature, RAW_P256_SIGNATURE_LEN),
  );
  await awaitWithSignal(
    context.trustVerifier.verifyOperationAppProof(asAppProof(proof), signal, bootProof),
    signal,
  );
  const payload = parseStrictJson<OperationProofPayload>(
    proof.proof_payload,
    OPERATION_PROOF_KEYS,
  );
  if (
    payload.type !== TVC_APP_PROOF_TYPE ||
    payload.version !== API_VERSION ||
    payload.request_id !== request.request_id ||
    payload.request_digest !== encodeLowerHex(requestDigest(request)) ||
    payload.result_digest !== encodeLowerHex(resultDigest(requireHex(response.encrypted_result))) ||
    payload.operation !== request.operation.type
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  return payload;
}

export async function executeOperationEnvelope(
  context: OperationExecutionContext,
  operation: Operation,
  sealedSeed?: SealedSeed,
  signal?: AbortSignal,
): Promise<{ plaintext: string; sealedSeedDigest: string }> {
  const { request, responseSecret, grant } = await prepareRequest(
    context,
    operation,
    sealedSeed,
    signal,
  );
  try {
    signal?.throwIfAborted();
    const requestBody = canonicalizeJsonValue(request);
    const quorum = parseQosP256Public(
      requireHex(context.info.quorum_public_key, QOS_P256_PUBLIC_LEN),
    );
    const ciphertext = qosEncrypt(quorum.encryption, te.encode(requestBody));
    const encrypted = encryptedRequest(context.info, encodeLowerHex(ciphertext), grant);
    checkRequestSize(context.info, enclaveRequestBytes(context, encrypted));
    // The ciphertext is hex, so it cannot exceed twice the byte ceiling;
    // RESPONSE_ENVELOPE_SLACK covers the surrounding JSON and App Proof.
    const maxResponseBytes = BigInt(context.info.max_encrypted_response_bytes);
    const { responseText, bootProof } = await sendOperation(
      context.backend,
      encrypted,
      context.operations.walletDescriptor,
      context.transport,
      maxResponseBytes * 2n + RESPONSE_ENVELOPE_SLACK,
      signal,
    );
    const response = parseStrictJson<EncryptedResponse>(responseText, ENCRYPTED_RESPONSE_KEYS);
    if (
      response.version !== API_VERSION ||
      !bytesEqual(
        requireHex(response.request_id, SHA256_LEN),
        requireHex(request.request_id, SHA256_LEN),
      )
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    const encryptedResult = requireHex(response.encrypted_result);
    if (BigInt(encryptedResult.length) > maxResponseBytes) {
      throw new TvcError("ResponseTooLarge");
    }
    const proof = await verifyOperationProof(context, request, response, bootProof, signal);
    let plaintext: string;
    try {
      plaintext = td.decode(qosDecrypt(responseSecret, encryptedResult));
    } catch {
      throw new TvcError("InvalidEncryptedEnvelope");
    }
    if (!isRfc8785(plaintext)) throw new TvcError("InvalidCanonicalJson");
    return { plaintext, sealedSeedDigest: proof.sealed_seed_digest };
  } finally {
    responseSecret.fill(0);
  }
}
