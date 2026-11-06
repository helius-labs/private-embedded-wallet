import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { RAW_P256_SIGNATURE_LEN, SEC1_UNCOMPRESSED_LEN } from "../protocol/constants.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";

export function parseUncompressedSec1(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    throw new SprEmbeddedWalletError("CompressedKeyRejected");
  }
  if (bytes.length !== SEC1_UNCOMPRESSED_LEN || bytes[0] !== 0x04) {
    throw new SprEmbeddedWalletError("InvalidPublicKey");
  }
  try {
    p256.ProjectivePoint.fromHex(bytes);
  } catch {
    throw new SprEmbeddedWalletError("InvalidPublicKey");
  }
  return bytes;
}

function parseRawLowS(signature: Uint8Array) {
  if (signature.length !== RAW_P256_SIGNATURE_LEN) {
    if (signature.length > 0 && signature[0] === 0x30) {
      throw new SprEmbeddedWalletError("DerSignatureRejected");
    }
    throw new SprEmbeddedWalletError("InvalidSignature");
  }
  const sig = p256.Signature.fromCompact(signature);
  if (sig.hasHighS()) {
    throw new SprEmbeddedWalletError("HighSSignature");
  }
  return sig;
}

export function signP256Prehash(secret: Uint8Array, digest: Uint8Array): Uint8Array {
  const sig = p256.sign(digest, secret, { lowS: true, prehash: false });
  return sig.toCompactRawBytes();
}

export function verifyP256Prehash(
  publicSec1: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array,
): void {
  parseUncompressedSec1(publicSec1);
  const sig = parseRawLowS(signature);
  if (!p256.verify(sig, digest, publicSec1, { prehash: false })) {
    throw new SprEmbeddedWalletError("InvalidSignature");
  }
}

export function signP256Message(secret: Uint8Array, message: Uint8Array): Uint8Array {
  return signP256Prehash(secret, sha256(message));
}

export function verifyP256Message(
  publicSec1: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  verifyP256Prehash(publicSec1, sha256(message), signature);
}
