import { sha256 } from "@noble/hashes/sha256";
import {
  CLIENT_AUTH_DOMAIN,
  PROVISIONING_AUTH_DOMAIN,
  RELEASE_POLICY_DOMAIN,
  REQUEST_DIGEST_DOMAIN,
  RESULT_DIGEST_DOMAIN,
  SHA256_LEN,
  SEALED_SEED_DIGEST_DOMAIN,
  WALLET_GRANT_DOMAIN,
} from "./constants.js";
import { canonicalizeJsonValue } from "./jcs.js";
import { encodeLowerHex } from "./hex.js";
import { TvcError } from "./error.js";

const te = new TextEncoder();

function domainSeparatedHash(domain: string, payload: Uint8Array): Uint8Array {
  const domainBytes = te.encode(domain);
  const input = new Uint8Array(domainBytes.length + 1 + payload.length);
  input.set(domainBytes, 0);
  input[domainBytes.length] = 0;
  input.set(payload, domainBytes.length + 1);
  return sha256(input);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function requestDigest(request: object): Uint8Array {
  const cloned = structuredClone(request) as Record<string, unknown>;
  const authorization = cloned.authorization as Record<string, unknown> | undefined;
  if (!authorization || typeof authorization !== "object") {
    throw new TvcError("InvalidCanonicalJson");
  }
  delete authorization.signature;
  if (!("client_key_id" in authorization) || !("scheme" in authorization)) {
    throw new TvcError("InvalidCanonicalJson");
  }
  return domainSeparatedHash(REQUEST_DIGEST_DOMAIN, te.encode(canonicalizeJsonValue(cloned)));
}

export function clientAuthDigest(requestDigestBytes: Uint8Array): Uint8Array {
  return sha256(clientAuthMessage(requestDigestBytes));
}

/** Exact bytes that WebCrypto ECDSA hashes once with SHA-256 for client auth. */
export function clientAuthMessage(requestDigestBytes: Uint8Array): Uint8Array {
  if (requestDigestBytes.length !== SHA256_LEN) throw new TvcError("InvalidDigest");
  const domain = te.encode(CLIENT_AUTH_DOMAIN);
  return concatBytes([domain, Uint8Array.of(0), requestDigestBytes]);
}

export function resultDigest(encryptedResult: Uint8Array): Uint8Array {
  return domainSeparatedHash(RESULT_DIGEST_DOMAIN, encryptedResult);
}

export function releasePolicyDigest(policyJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(RELEASE_POLICY_DOMAIN, policyJcs);
}


/** Exact `WalletDescriptor` digest the provisioner signs. */
export function descriptorDigest(descriptor: object): Uint8Array {
  const value = structuredClone(descriptor) as Record<string, unknown>;
  delete value.provisioning_signature;
  return domainSeparatedHash(PROVISIONING_AUTH_DOMAIN, te.encode(canonicalizeJsonValue(value)));
}

/** The grant key signs the grant without its own signature field. */
export function walletGrantDigest(grant: object): Uint8Array {
  const value = structuredClone(grant) as Record<string, unknown>;
  delete value.signature;
  return domainSeparatedHash(WALLET_GRANT_DOMAIN, te.encode(canonicalizeJsonValue(value)));
}

/** Grant identity the enclave derives from the client public key. */
export function clientKeyIdFor(clientPublicKey: Uint8Array): string {
  return `tvc-browser-p256-${encodeLowerHex(sha256(clientPublicKey).slice(0, 16))}`;
}

/** Digest of the exact sealed-state wire bytes. */
export function sealedSeedDigest(sealedState: Uint8Array): Uint8Array {
  return domainSeparatedHash(SEALED_SEED_DIGEST_DOMAIN, sealedState);
}
