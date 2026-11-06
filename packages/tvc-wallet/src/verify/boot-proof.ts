import { sha384 } from "@noble/hashes/sha512";
import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public } from "../crypto/qos.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";
import {
  MAX_CLOCK_SKEW_MS,
  SHA256_LEN,
  SHA384_LEN,
  TVC_APP_PROOF_SCHEME,
} from "../protocol/constants.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { isRfc8785 } from "../protocol/jcs.js";
import {
  type CborValue,
  decodeAwsNitroAttestationCbor,
  decodeCbor,
} from "./internal/cbor.js";
import {
  type CoseSign1,
  type TurnkeyAppProofWire,
  type TurnkeyBootProofWire,
  verifyTurnkeyAwsAttestation,
} from "./internal/turnkey-proof-seam.js";

const QOS_LIVE_MANIFEST_PCR_COMMITMENT_DOMAIN = "qos-live-manifest-pcr-commitment-v1";
const QOS_LIVE_MANIFEST_COMMITMENT_PCR_INDEX = 17;
const QOS_ATTESTABLE_PCR_COUNT = 32;
const QOS_EPHEMERAL_PUBLIC_KEY_LENGTH = 130;
/**
 * A Boot Proof is immutable evidence for one enclave boot and remains valid
 * for that replica's lifetime. Freshness comes from the unpredictable QOS
 * challenge (or the request-bound operation App Proof), which proves current
 * possession of the attested ephemeral key. Expiring the Boot Proof by wall
 * clock would make every healthy long-running replica unverifiable.
 */

type QosIdentityPcrIndex = 0 | 1 | 2 | 3;

/**
 * Independently trusted Nitro measurements for the expected QOS deployment.
 * Never populate these values from `/v1/info` or from the Boot Proof itself.
 */
export type QosIdentityPcrs = Readonly<Record<QosIdentityPcrIndex, string>>;

type VerifyBootProofInput = {
  appProof: TurnkeyAppProofWire;
  bootProof: TurnkeyBootProofWire;
  allowedManifestSha256: readonly string[];
  expectedPcrs: QosIdentityPcrs;
  /** Verifier clock. Rejects future attestations and validates the certificate chain now. */
  nowMs: bigint;
};

type AwsNitroAttestationDocument = Map<string | number, CborValue>;

type DecodedBootProof = {
  coseSign1: CoseSign1;
  attestation: AwsNitroAttestationDocument;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
};

/**
 * Verifies a replica's Boot Proof with Turnkey's AWS Nitro helpers plus
 * independently pinned QOS manifest/PCR checks.
 */
export async function verifyBootProof(input: VerifyBootProofInput): Promise<void> {
  let stage = "app-proof";
  try {
    verifyTvcAppProof(input.appProof);
    stage = "decode";
    const decoded = decodeBootProof(input.bootProof);
    stage = "shape";
    validateAttestationShape(decoded.attestation);
    stage = "timestamp";
    assertAttestationFreshness(decoded.attestation, input.nowMs);

    stage = "bindings";
    verifyProofBindings(input, decoded.attestation);

    // Last, because it is the only check that leaves this process and the only
    // one that needs the pinned AWS root. Every check above is a local
    // predicate on the same bytes, so running them first only rejects sooner.
    // The chain must be valid on the verifier's clock, never on a timestamp
    // the attestation document supplies about itself.
    stage = "aws-chain";
    await verifyTurnkeyAwsAttestation(
      decoded.coseSign1,
      decoded.certificate,
      decoded.cabundle,
      Number(input.nowMs),
    );
  } catch {
    // Stage names contain no proof bytes or remote error text. They make a
    // fail-closed deployment diagnosable without widening the public error
    // code or leaking attestation material into application logs.
    throw new SprEmbeddedWalletError("BootProofUnverified", stage);
  }
}

export function computeQosLiveManifestCommitmentPcr(
  manifestDigest: Uint8Array,
  ephemeralPublicKey: Uint8Array,
): Uint8Array {
  if (manifestDigest.length !== SHA256_LEN) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  if (ephemeralPublicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const commitmentPreimage = new TextEncoder().encode(
    `{"domain":"${QOS_LIVE_MANIFEST_PCR_COMMITMENT_DOMAIN}","ephemeralPublicKey":"${encodeLowerHex(
      ephemeralPublicKey,
    )}","manifestHash":"${encodeLowerHex(manifestDigest)}"}`,
  );
  const commitment = sha384(commitmentPreimage);
  const extensionInput = new Uint8Array(SHA384_LEN + commitment.length);
  extensionInput.set(commitment, SHA384_LEN);
  return sha384(extensionInput);
}

function verifyTvcAppProof(appProof: TurnkeyAppProofWire): void {
  if (appProof.scheme !== TVC_APP_PROOF_SCHEME || !isRfc8785(appProof.proofPayload)) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const publicKey = decodeLowerHex(appProof.publicKey);
  const signature = decodeLowerHex(appProof.signature);
  const qosPublic = parseQosP256Public(publicKey);
  verifyP256Message(qosPublic.signing, new TextEncoder().encode(appProof.proofPayload), signature);
}

function decodeBootProof(bootProof: TurnkeyBootProofWire): DecodedBootProof {
  const decodedCose = decodeCbor(decodeBase64(bootProof.awsAttestationDocB64));
  if (!Array.isArray(decodedCose) || decodedCose.length !== 4) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const [protectedHeaders, , payload, signature] = decodedCose;
  const coseSign1: CoseSign1 = {
    protectedHeaders: asBytes(protectedHeaders),
    payload: asBytes(payload),
    signature: asBytes(signature),
  };
  const decoded = decodeAwsNitroAttestationCbor(coseSign1.payload);
  if (!(decoded instanceof Map)) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const certificate = asBytes(decoded.get("certificate"));
  const cabundle = decoded.get("cabundle");
  if (!Array.isArray(cabundle) || cabundle.length === 0) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  return { coseSign1, attestation: decoded, certificate, cabundle: cabundle.map(asBytes) };
}

function validateAttestationShape(attestation: AwsNitroAttestationDocument): void {
  const moduleId = attestation.get("module_id");
  if (typeof moduleId !== "string" || moduleId.length === 0) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  if (attestation.get("digest") !== "SHA384") {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const timestamp = attestation.get("timestamp");
  if (typeof timestamp !== "number" || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const nonce = attestation.get("nonce");
  if (nonce !== null && nonce !== undefined) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const pcrs = attestation.get("pcrs");
  if (!(pcrs instanceof Map) || pcrs.size !== QOS_ATTESTABLE_PCR_COUNT) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  for (let index = 0; index < QOS_ATTESTABLE_PCR_COUNT; index += 1) {
    getPcr(attestation, index);
  }
}

function assertAttestationFreshness(
  attestation: AwsNitroAttestationDocument,
  nowMs: bigint,
): void {
  // Narrowed to Number below for the certificate-chain check, so anything past
  // the safe-integer range would silently lose precision.
  if (nowMs <= 0n || nowMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const timestamp = BigInt(attestation.get("timestamp") as number);
  if (timestamp > nowMs + MAX_CLOCK_SKEW_MS) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
}

function verifyProofBindings(
  input: VerifyBootProofInput,
  attestation: AwsNitroAttestationDocument,
): void {
  if (input.allowedManifestSha256.length === 0) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const allowed = input.allowedManifestSha256.map((value) =>
    decodeFixedLowerHex(value, SHA256_LEN),
  );
  // QOS commits VersionedManifest::manifest_hash(), not SHA-256 over the
  // serialized Borsh bytes carried in qosManifestB64.
  const manifestDigest = asBytes(attestation.get("user_data"));
  if (
    manifestDigest.length !== SHA256_LEN ||
    !allowed.some((digest) => bytesEqual(digest, manifestDigest))
  ) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }

  const attestedPublicKey = asBytes(attestation.get("public_key"));
  if (attestedPublicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  const appPublicKey = decodeFixedLowerHex(
    input.appProof.publicKey,
    QOS_EPHEMERAL_PUBLIC_KEY_LENGTH,
  );
  const bootPublicKey = decodeFixedLowerHex(
    input.bootProof.ephemeralPublicKeyHex,
    QOS_EPHEMERAL_PUBLIC_KEY_LENGTH,
  );
  if (!bytesEqual(appPublicKey, bootPublicKey) || !bytesEqual(bootPublicKey, attestedPublicKey)) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }

  for (const index of [0, 1, 2, 3] as const) {
    const expected = decodeFixedLowerHex(input.expectedPcrs[index], SHA384_LEN);
    if (!bytesEqual(expected, getPcr(attestation, index))) {
      throw new SprEmbeddedWalletError("BootProofUnverified");
    }
  }

  const expectedLivePcr = computeQosLiveManifestCommitmentPcr(manifestDigest, attestedPublicKey);
  if (!bytesEqual(expectedLivePcr, getPcr(attestation, QOS_LIVE_MANIFEST_COMMITMENT_PCR_INDEX))) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
}

function getPcr(attestation: AwsNitroAttestationDocument, index: number): Uint8Array {
  // NSM keys the PCR map by CBOR unsigned integer, so the lookup is by number.
  // A text-keyed map is outside the format and is rejected here.
  const pcrs = attestation.get("pcrs");
  if (!(pcrs instanceof Map)) throw new SprEmbeddedWalletError("BootProofUnverified");
  const bytes = asBytes(pcrs.get(index));
  if (bytes.length !== SHA384_LEN) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  return bytes;
}

function decodeFixedLowerHex(value: string, length: number): Uint8Array {
  const bytes = decodeLowerHex(value);
  if (bytes.length !== length) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  return bytes;
}

function decodeBase64(value: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new SprEmbeddedWalletError("BootProofUnverified");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new SprEmbeddedWalletError("BootProofUnverified");
}
