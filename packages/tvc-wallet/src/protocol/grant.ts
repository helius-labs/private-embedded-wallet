import { signP256Prehash } from "../crypto/p256.js";
import { encodeDecimalU64 } from "./decimal.js";
import { descriptorDigest, walletGrantDigest } from "./digest.js";
import { TvcError } from "./error.js";
import { encodeLowerHex } from "./hex.js";
import { p256SecretFromKeyFile } from "./key-file.js";
import type { WalletDescriptor, WalletGrant } from "./types.js";

/** The enclave refuses a grant that lives longer (`MAX_WALLET_GRANT_LIFETIME_MS`). */
export const MAX_WALLET_GRANT_LIFETIME_MS = 3_600_000n;

/**
 * The development wallet-grant key the enclave is built with (`GRANT_PUBLIC` in
 * `apps/privacy-wallet/src/operations/mod.rs`). A grant signed by any other key
 * is refused there, so `walletGrantSecret` refuses it here first.
 */
export const DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY =
  "04d92dfa9ba9aafd471ff9ffbf454b9a11b14858a8c2edb4f79a4ea4b4dba8ca5cac9ec06d9bb5576db72d07e087ac6aadf72e4eb31323aafaf9dbd133d26f4dc7";

export type WalletGrantInput = {
  readonly descriptor: WalletDescriptor;
  readonly clientKeyId: string;
  /** The account the issuer attributes the wallet to; the enclave does not read it. */
  readonly projectId: string;
  readonly issuedAtMs: bigint;
  readonly lifetimeMs: bigint;
};

/**
 * The wallet-grant secret from a key file (`{"private_key": hex}`), checked to
 * be the key the enclave expects. The caller wipes it after use.
 */
export function walletGrantSecret(
  keyJson: string,
  expectedPublicKey: string = DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY,
): Uint8Array {
  return p256SecretFromKeyFile(keyJson, expectedPublicKey, {
    invalid: "InvalidWalletGrantKey",
    wrong: "WrongWalletGrantKey",
  });
}

/**
 * A grant for one descriptor and client key, signed with the grant key's
 * secret as the 64-byte raw low-S P-256 signature over `walletGrantDigest`.
 */
export function signWalletGrant(input: WalletGrantInput, secret: Uint8Array): WalletGrant {
  if (input.lifetimeMs <= 0n || input.lifetimeMs > MAX_WALLET_GRANT_LIFETIME_MS) {
    throw new TvcError("InvalidDescriptor", "grant lifetime must be positive and at most one hour");
  }
  const unsigned: WalletGrant = {
    version: 1,
    descriptor_digest: encodeLowerHex(descriptorDigest(input.descriptor)),
    client_key_id: input.clientKeyId,
    project_id: input.projectId,
    issued_at_ms: encodeDecimalU64(input.issuedAtMs),
    expires_at_ms: encodeDecimalU64(input.issuedAtMs + input.lifetimeMs),
    signature: "",
  };
  return Object.freeze({
    ...unsigned,
    signature: encodeLowerHex(signP256Prehash(secret, walletGrantDigest(unsigned))),
  });
}
