import type {
  SignTvcRequestInput,
  SprRequestSigner,
} from "../client/operation-executor.js";
import { clientAuthMessage, requestDigest } from "../protocol/digest.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";

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
): string {
  if (input.request.authorization.client_key_id !== clientKeyId) {
    throw new SprEmbeddedWalletError("OperationNotAllowed");
  }
  const expected = clientAuthMessage(requestDigest(input.request));
  if (input.clientAuthMessage !== expected) {
    throw new SprEmbeddedWalletError("OperationNotAllowed");
  }
  return expected;
}

/** Normalizes a 64-byte `r||s` signature to low-S, the only form TVC accepts. */
export function compactLowS(signature: ArrayBuffer | Uint8Array): Uint8Array {
  const bytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);
  if (bytes.length !== 64) throw new SprEmbeddedWalletError("InvalidSignatureEncoding");
  let r = 0n;
  let s = 0n;
  for (const byte of bytes.slice(0, 32)) r = (r << 8n) | BigInt(byte);
  for (const byte of bytes.slice(32)) s = (s << 8n) | BigInt(byte);
  if (r === 0n || r >= P256_ORDER || s === 0n || s >= P256_ORDER) {
    throw new SprEmbeddedWalletError("InvalidSignature");
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

/** A P-256 client key: a Turnkey session key, or the testkit's. */
export type SprRequestKey = {
  /** `clientKeyIdFor` of the uncompressed P-256 public key the descriptor lists. */
  readonly clientKeyId: string;
  /** ECDSA over SHA-256 of the message's UTF-8 bytes, returned as 64-byte `r||s`. */
  sign(message: string): Promise<Uint8Array>;
};

/**
 * The request signer for a key. The message and the low-S normalization stay
 * here, so a key supplies its signature and nothing else.
 */
export function createSprRequestSigner(key: SprRequestKey): SprRequestSigner {
  return {
    clientKeyId: key.clientKeyId,
    async signRequest(input: SignTvcRequestInput) {
      const message = signedRequestMessage(input, key.clientKeyId);
      return compactLowS(await key.sign(message));
    },
  };
}
