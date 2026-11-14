// Synthetic AWS Nitro attestation builders shared by the Boot Proof tests.
// Excluded from the published build; imported only by *.test.ts.
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { signP256Message } from "../crypto/p256.js";
import { TVC_APP_PROOF_SCHEME } from "../protocol/constants.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import type { CborValue } from "./internal/cbor.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "./internal/turnkey-proof-seam.js";
import { computeQosLiveManifestCommitmentPcr } from "./boot-proof.js";

export const NOW_MS = 1_750_000_000_000n;
const ATTESTATION_TIMESTAMP = 1_749_999_990_000;

function encodeHead(major: number, argument: number): number[] {
  const prefix = major << 5;
  if (argument < 24) return [prefix | argument];
  if (argument < 0x100) return [prefix | 24, argument];
  if (argument < 0x10000) return [prefix | 25, argument >> 8, argument & 0xff];
  if (argument < 0x100000000) {
    return [prefix | 26, (argument >>> 24) & 0xff, (argument >>> 16) & 0xff, (argument >>> 8) & 0xff, argument & 0xff];
  }
  const high = Math.floor(argument / 0x100000000);
  return [
    prefix | 27,
    (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (argument >>> 24) & 0xff, (argument >>> 16) & 0xff, (argument >>> 8) & 0xff, argument & 0xff,
  ];
}

function encodeCbor(value: CborValue): number[] {
  if (value === null) return [0xf6];
  if (value === true) return [0xf5];
  if (value === false) return [0xf4];
  if (typeof value === "number") {
    return value < 0 ? encodeHead(1, -1 - value) : encodeHead(0, value);
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return [...encodeHead(3, bytes.length), ...bytes];
  }
  if (value instanceof Uint8Array) return [...encodeHead(2, value.length), ...value];
  if (Array.isArray(value)) {
    return value.reduce<number[]>((out, item) => [...out, ...encodeCbor(item)], encodeHead(4, value.length));
  }
  const out = encodeHead(5, value.size);
  for (const [key, item] of value) out.push(...encodeCbor(key), ...encodeCbor(item));
  return out;
}

function base64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}

export function label(text: string): Uint8Array {
  return sha256(new TextEncoder().encode(text));
}

export function pcr(fill: number): Uint8Array {
  return new Uint8Array(48).fill(fill);
}

export const EXPECTED_PCRS = {
  0: encodeLowerHex(pcr(0x44)),
  1: encodeLowerHex(pcr(0x55)),
  2: encodeLowerHex(pcr(0x66)),
  3: encodeLowerHex(pcr(0x77)),
} as const;

export const MANIFEST_DIGEST = label("boot-proof-manifest");
const ENCRYPTION_SECRET = label("boot-proof-encryption");
const SIGNING_SECRET = label("boot-proof-signing");
const EPHEMERAL_PUBLIC_KEY = Uint8Array.from([
  ...p256.getPublicKey(ENCRYPTION_SECRET, false),
  ...p256.getPublicKey(SIGNING_SECRET, false),
]);

export type AttestationOverrides = {
  entries?: Record<string, CborValue>;
  pcrOverrides?: Record<number, Uint8Array>;
  pcrCount?: number;
  coseLength?: number;
};

function attestationPcrs(overrides: AttestationOverrides): Map<string | number, CborValue> {
  const identity: Record<number, Uint8Array> = { 0: pcr(0x44), 1: pcr(0x55), 2: pcr(0x66), 3: pcr(0x77) };
  const live = computeQosLiveManifestCommitmentPcr(MANIFEST_DIGEST, EPHEMERAL_PUBLIC_KEY);
  const pcrs = new Map<string | number, CborValue>();
  for (let index = 0; index < (overrides.pcrCount ?? 32); index += 1) {
    pcrs.set(index, overrides.pcrOverrides?.[index] ?? identity[index] ?? (index === 17 ? live : pcr(0)));
  }
  return pcrs;
}

export function bootProof(overrides: AttestationOverrides = {}): TurnkeyBootProofWire {
  const payload = new Map<string | number, CborValue>([
    ["module_id", "i-0000000000000000-enc0000000000000000"],
    ["digest", "SHA384"],
    ["timestamp", ATTESTATION_TIMESTAMP],
    ["pcrs", attestationPcrs(overrides)],
    ["certificate", label("leaf-certificate")],
    ["cabundle", [label("root-certificate")]],
    ["public_key", EPHEMERAL_PUBLIC_KEY],
    ["user_data", MANIFEST_DIGEST],
    ["nonce", null],
  ]);
  for (const [key, value] of Object.entries(overrides.entries ?? {})) payload.set(key, value);

  const cose: CborValue[] = [
    Uint8Array.from([0xa1, 0x01, 0x38, 0x22]),
    new Map(),
    Uint8Array.from(encodeCbor(payload)),
    new Uint8Array(96).fill(0x11),
  ];
  return {
    awsAttestationDocB64: base64(encodeCbor(cose.slice(0, overrides.coseLength ?? 4))),
    ephemeralPublicKeyHex: encodeLowerHex(EPHEMERAL_PUBLIC_KEY),
    qosManifestB64: "unused",
    qosManifestEnvelopeB64: "unused",
    deploymentLabel: "boot-proof-test",
    enclaveApp: "wallet-dev",
    owner: "zolana",
    createdAt: { seconds: "1750000000", nanos: "0" },
  } as TurnkeyBootProofWire;
}

export function appProof(): TurnkeyAppProofWire {
  const proofPayload = canonicalizeJsonValue({
    type: "spr.tvc.qos_ping.v1",
    version: 1,
    challenge: encodeLowerHex(label("challenge")),
  });
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: encodeLowerHex(EPHEMERAL_PUBLIC_KEY),
    proofPayload,
    signature: encodeLowerHex(
      signP256Message(SIGNING_SECRET, new TextEncoder().encode(proofPayload)),
    ),
  } as TurnkeyAppProofWire;
}
