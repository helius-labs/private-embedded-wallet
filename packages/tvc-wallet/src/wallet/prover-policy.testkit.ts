import { encodeLowerHex } from "../protocol/hex.js";
import type { SignedProverPolicyFile } from "../protocol/types.js";

export const POLICY_URL = "https://policy.test/tee-policy/devnet.json";

const hex = (value: unknown): string => encodeLowerHex(new TextEncoder().encode(JSON.stringify(value)));
const signatures = [{ public_key: "11".repeat(32), signature: "22".repeat(64) }];

/**
 * A policy file shaped as a network publishes it: a release part and a
 * freshness part over it, fresh until `freshUntil` (by default `expiresAt`)
 * and issued at `issuedAt` (by default an hour before that). The client never
 * checks signatures or the release hash (the enclave does), so these are
 * placeholders.
 */
export function policyFile({
  version = 1,
  maxAgeSecs = 600,
  expiresAt,
  freshUntil = expiresAt,
  issuedAt = Math.max(0, freshUntil - 3_600),
}: {
  version?: number;
  maxAgeSecs?: number;
  expiresAt: number;
  freshUntil?: number;
  issuedAt?: number;
}): SignedProverPolicyFile {
  const release = {
    network: "devnet",
    version,
    expires_at: expiresAt,
    freshness: { public_keys: ["33".repeat(32)], threshold: 1, max_lifetime_secs: 259_200 },
    policy: { platform: "aws-nitro", measurements: [], gpu: "optional", max_age_secs: maxAgeSecs },
  };
  const freshness = {
    network: "devnet",
    release_version: version,
    release_sha256: "00".repeat(32),
    issued_at: issuedAt,
    expires_at: freshUntil,
  };
  return { release: { payload: hex(release), signatures }, freshness: { payload: hex(freshness), signatures } };
}
