import {
  API_VERSION,
  EXPECTED_TURNKEY_TRUST_ROOT_ID,
  TVC_APP_PROOF_TYPE,
} from "../protocol/constants.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { releasePolicyDigest } from "../protocol/digest.js";
import { decodeLowerHex } from "../protocol/hex.js";
import { TvcError } from "../protocol/error.js";
import type {
  Network,
  PinnedReleaseAuthorities,
  ServiceInfo,
  SignedReleasePolicy,
} from "../protocol/types.js";
import { verifyP256Prehash } from "../crypto/p256.js";

export function policySigningDigest(policy: unknown): Uint8Array {
  return releasePolicyDigest(new TextEncoder().encode(canonicalizeJsonValue(policy)));
}

/**
 * Accepts `signed` only for `network`, at a threshold of `authorities`, while
 * `nowMs` is inside its validity window. Mirrors `verify_signed_release_policy`
 * in `crates/protocol`, check for check.
 */
export function verifySignedReleasePolicy(
  signed: SignedReleasePolicy,
  authorities: PinnedReleaseAuthorities,
  network: Network,
  nowMs: bigint,
): void {
  if (signed.policy.version !== API_VERSION) {
    throw new TvcError("UnsupportedVersion");
  }
  if (signed.policy.network !== network) {
    throw new TvcError("NetworkMismatch");
  }
  if (authorities.threshold < 1 || authorities.keys.length === 0) {
    throw new TvcError("ReleasePolicyInvalid");
  }
  if (signed.authoritySetId !== authorities.authoritySetId) {
    throw new TvcError("ReleasePolicyInvalid");
  }
  if (signed.policy.turnkeyTrustRootId !== EXPECTED_TURNKEY_TRUST_ROOT_ID) {
    throw new TvcError("ReleasePolicyInvalid");
  }
  if (
    BigInt(signed.policy.revocationEpoch) <
    BigInt(authorities.minimumRevocationEpoch)
  ) {
    throw new TvcError("ReleasePolicyInvalid");
  }
  const validFrom = BigInt(signed.policy.validFromMs);
  const expires = BigInt(signed.policy.expiresAtMs);
  if (nowMs < validFrom || nowMs > expires) {
    throw new TvcError("ExpiredRequest");
  }
  if (signed.signatures.length === 0) {
    throw new TvcError("ReleasePolicyInvalid");
  }

  const byId = new Map<string, Uint8Array>();
  for (const key of authorities.keys) {
    if (byId.has(key.keyId)) {
      throw new TvcError("ReleasePolicyInvalid");
    }
    byId.set(key.keyId, decodeLowerHex(key.publicKey));
  }

  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const signature of signed.signatures) {
    if (seen.has(signature.keyId)) duplicates.add(signature.keyId);
    seen.add(signature.keyId);
  }

  const digest = policySigningDigest(signed.policy);
  let accepted = 0;
  for (const signature of signed.signatures) {
    if (duplicates.has(signature.keyId)) continue;
    const publicKey = byId.get(signature.keyId);
    if (!publicKey) continue;
    verifyP256Prehash(publicKey, digest, decodeLowerHex(signature.signature));
    accepted += 1;
  }
  if (accepted < authorities.threshold) {
    throw new TvcError("ReleasePolicyInvalid");
  }
}

/**
 * Binds every security field of `/v1/info` to a policy that has already
 * verified for the client's network, so discovery must name that network too.
 */
export function bindDiscoveryToPolicy(
  info: ServiceInfo,
  signed: SignedReleasePolicy,
): void {
  const policy = signed.policy;
  if (info.network !== policy.network) {
    throw new TvcError("NetworkMismatch");
  }
  if (info.version !== API_VERSION) {
    throw new TvcError("UnsupportedVersion");
  }
  if (info.proof_type !== TVC_APP_PROOF_TYPE) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (info.release_id !== policy.releaseId) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (info.security_domain_id !== policy.securityDomainId) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (info.quorum_key_id !== policy.quorumKeyId) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (info.quorum_key_epoch !== policy.quorumKeyEpoch) {
    throw new TvcError("QuorumKeyEpochMismatch");
  }
  if (info.quorum_public_key !== policy.quorumPublicKey) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (!policy.acceptedManifestDigests.includes(info.manifest_digest)) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (!policy.acceptedExecutableDigests.includes(info.executable_digest)) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (
    info.supported_operations.length !== policy.allowedOperations.length ||
    info.supported_operations.some(
      (operation, index) => operation !== policy.allowedOperations[index],
    )
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (
    BigInt(info.max_encrypted_request_bytes) !==
      BigInt(policy.maxEncryptedRequestBytes) ||
    BigInt(info.max_encrypted_response_bytes) !==
      BigInt(policy.maxEncryptedResponseBytes)
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
}
