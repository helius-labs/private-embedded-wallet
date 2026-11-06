import { gcm } from "@noble/ciphers/aes";
import { p256 } from "@noble/curves/p256";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import {
  AES_GCM_NONCE_LEN,
  AES_GCM_TAG_LEN,
  QOS_ENCRYPTION_HMAC_MESSAGE,
  QOS_P256_PUBLIC_LEN,
  SEC1_UNCOMPRESSED_LEN,
} from "../protocol/constants.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";
import { parseUncompressedSec1 } from "./p256.js";

const te = new TextEncoder();
const ENVELOPE_HEADER_LEN = AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN + 4;

type QosP256Public = {
  encryption: Uint8Array;
  signing: Uint8Array;
};

export function parseQosP256Public(bytes: Uint8Array): QosP256Public {
  if (bytes.length !== QOS_P256_PUBLIC_LEN) {
    throw new SprEmbeddedWalletError("InvalidPublicKey");
  }
  const encryption = parseUncompressedSec1(
    bytes.slice(0, SEC1_UNCOMPRESSED_LEN)
  );
  const signing = parseUncompressedSec1(bytes.slice(SEC1_UNCOMPRESSED_LEN));
  return { encryption, signing };
}

function sharedX(secret: Uint8Array, publicSec1: Uint8Array): Uint8Array {
  const shared = p256.getSharedSecret(secret, publicSec1, false);
  return shared.slice(1, 33);
}

function cipherKey(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array,
  sharedSecret: Uint8Array
): Uint8Array {
  const preImage = new Uint8Array(
    ephemeralPublic.length + receiverPublic.length + sharedSecret.length
  );
  preImage.set(ephemeralPublic, 0);
  preImage.set(receiverPublic, ephemeralPublic.length);
  preImage.set(sharedSecret, ephemeralPublic.length + receiverPublic.length);
  return hmac(sha512, preImage, te.encode(QOS_ENCRYPTION_HMAC_MESSAGE)).slice(
    0,
    32
  );
}

function aad(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array
): Uint8Array {
  const out = new Uint8Array(
    ephemeralPublic.length + receiverPublic.length + 2
  );
  out.set(ephemeralPublic, 0);
  out[ephemeralPublic.length] = ephemeralPublic.length;
  out.set(receiverPublic, ephemeralPublic.length + 1);
  out[out.length - 1] = receiverPublic.length;
  return out;
}

function encodeU32Le(value: number): Uint8Array {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value, true);
  return out;
}

function decodeU32Le(bytes: Uint8Array, offset: number): number {
  // Bounded against the view, not the buffer behind it: a DataView built from
  // `bytes.buffer` alone reads past a subarray's end into neighbouring memory.
  // No current caller can reach that -- decodeQosEnvelope checks the header
  // length first -- so this guards the function's own contract against a future
  // caller or a weakened guard, and no test exercises it through the envelope.
  if (offset < 0 || bytes.length - offset < 4) {
    throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(
    0,
    true
  );
}

function encodeQosEnvelope(
  nonce: Uint8Array,
  ephemeralPublic: Uint8Array,
  encryptedMessage: Uint8Array
): Uint8Array {
  if (nonce.length !== AES_GCM_NONCE_LEN || ephemeralPublic.length !== SEC1_UNCOMPRESSED_LEN) {
    throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  }
  const out = new Uint8Array(ENVELOPE_HEADER_LEN + encryptedMessage.length);
  out.set(nonce, 0);
  out.set(ephemeralPublic, AES_GCM_NONCE_LEN);
  out.set(encodeU32Le(encryptedMessage.length), AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN);
  out.set(encryptedMessage, ENVELOPE_HEADER_LEN);
  return out;
}

function decodeQosEnvelope(bytes: Uint8Array): {
  nonce: Uint8Array;
  ephemeralSenderPublic: Uint8Array;
  encryptedMessage: Uint8Array;
} {
  if (bytes.length < ENVELOPE_HEADER_LEN) throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  const nonce = bytes.slice(0, AES_GCM_NONCE_LEN);
  const ephemeralSenderPublic = bytes.slice(AES_GCM_NONCE_LEN, ENVELOPE_HEADER_LEN - 4);
  const messageLen = decodeU32Le(bytes, ENVELOPE_HEADER_LEN - 4);
  if (bytes.length !== ENVELOPE_HEADER_LEN + messageLen)
    throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  const encryptedMessage = bytes.slice(ENVELOPE_HEADER_LEN);
  if (encryptedMessage.length < AES_GCM_TAG_LEN) {
    throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  }
  return { nonce, ephemeralSenderPublic, encryptedMessage };
}

export function qosEncryptWith(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array,
  ephemeralSecret: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  if (nonce.length !== AES_GCM_NONCE_LEN) {
    throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  }
  const receiver = parseUncompressedSec1(receiverEncryptionSec1);
  const ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  const shared = sharedX(ephemeralSecret, receiver);
  const key = cipherKey(ephemeralPublic, receiver, shared);
  const associated = aad(ephemeralPublic, receiver);
  const encryptedMessage = gcm(key, nonce, associated).encrypt(plaintext);
  return encodeQosEnvelope(nonce, ephemeralPublic, encryptedMessage);
}

export function qosEncrypt(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  return qosEncryptWith(
    receiverEncryptionSec1,
    plaintext,
    p256.utils.randomPrivateKey(),
    nonce
  );
}

export function qosDecrypt(
  receiverSecret: Uint8Array,
  envelopeBytes: Uint8Array
): Uint8Array {
  const envelope = decodeQosEnvelope(envelopeBytes);
  parseUncompressedSec1(envelope.ephemeralSenderPublic);
  const receiverPublic = p256.getPublicKey(receiverSecret, false);
  const shared = sharedX(receiverSecret, envelope.ephemeralSenderPublic);
  const key = cipherKey(envelope.ephemeralSenderPublic, receiverPublic, shared);
  const associated = aad(envelope.ephemeralSenderPublic, receiverPublic);
  try {
    return gcm(key, envelope.nonce, associated).decrypt(
      envelope.encryptedMessage
    );
  } catch {
    throw new SprEmbeddedWalletError("InvalidEncryptedEnvelope");
  }
}
