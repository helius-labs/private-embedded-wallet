import type {
  SignTvcRequestInput,
  TvcRequestSigner,
} from "../client/operation-executor.js";
import { clientAuthMessage, requestDigest } from "../protocol/digest.js";
import { TvcError } from "../protocol/error.js";
import { bytesEqual } from "../protocol/hex.js";

const P256_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);
const P256_HALF_ORDER = P256_ORDER >> 1n;

/**
 * Rederives the exact bytes this signer will sign from the request it was
 * shown, and refuses to sign anything else.
 *
 * The private key is the wallet's operation authority, so the signer must not
 * be a signing oracle for caller-supplied bytes: whatever it signs has to be a
 * function of a request the caller also disclosed in full.
 */
export function signedRequestMessage(
  input: SignTvcRequestInput,
  clientKeyId: string,
): Uint8Array {
  if (input.request.authorization.client_key_id !== clientKeyId) {
    throw new TvcError("OperationNotAllowed");
  }
  const expected = clientAuthMessage(requestDigest(input.request));
  if (!bytesEqual(input.clientAuthMessage, expected)) {
    throw new TvcError("OperationNotAllowed");
  }
  return expected;
}

/** Normalizes a 64-byte `r||s` signature to low-S, the only form TVC accepts. */
export function compactLowS(signature: ArrayBuffer | Uint8Array): Uint8Array {
  const bytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);
  if (bytes.length !== 64) throw new TvcError("InvalidSignatureEncoding");
  let r = 0n;
  let s = 0n;
  for (const byte of bytes.slice(0, 32)) r = (r << 8n) | BigInt(byte);
  for (const byte of bytes.slice(32)) s = (s << 8n) | BigInt(byte);
  if (r === 0n || r >= P256_ORDER || s === 0n || s >= P256_ORDER) {
    throw new TvcError("InvalidSignature");
  }
  if (s <= P256_HALF_ORDER) return bytes;
  s = P256_ORDER - s;
  const output = bytes.slice();
  for (let index = 63; index >= 32; index -= 1) {
    output[index] = Number(s & 0xffn);
    s >>= 8n;
  }
  return output;
}

/** A P-256 client key the caller holds, such as in a server's key store. */
export type TvcRequestKey = {
  /** `clientKeyIdFor` of the uncompressed P-256 public key the descriptor lists. */
  readonly clientKeyId: string;
  /** ECDSA over `SHA-256` of the message, returned as 64-byte `r||s`. */
  sign(message: Uint8Array): Promise<Uint8Array>;
};

/**
 * The request signer for a key the caller holds.
 *
 * The message and the low-S normalization stay here, so a caller outside the
 * browser supplies a key and nothing else. Reimplementing either would put the
 * canonical form in two places.
 */
export function createTvcRequestSigner(key: TvcRequestKey): TvcRequestSigner {
  return {
    clientKeyId: key.clientKeyId,
    async signRequest(input: SignTvcRequestInput) {
      const message = signedRequestMessage(input, key.clientKeyId);
      return compactLowS(await key.sign(message));
    },
  };
}
