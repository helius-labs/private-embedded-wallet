import { encodeLowerHex } from "../protocol/hex.js";
import type { SignedProverPolicyFile } from "../protocol/types.js";

export const POLICY_URL = "https://policy.test/tee-policy/devnet.json";

/**
 * A policy file shaped as a network publishes it. The client never checks its
 * signatures (the enclave does), so these are placeholders.
 */
export function policyFile({
  version = 1,
  maxAgeSecs = 600,
  expiresAt,
}: {
  version?: number;
  maxAgeSecs?: number;
  expiresAt: number;
}): SignedProverPolicyFile {
  const payload = {
    network: "devnet",
    version,
    expires_at: expiresAt,
    policy: { platform: "aws-nitro", measurements: [], gpu: "optional", max_age_secs: maxAgeSecs },
  };
  return {
    payload: encodeLowerHex(new TextEncoder().encode(JSON.stringify(payload))),
    signatures: [{ public_key: "11".repeat(32), signature: "22".repeat(64) }],
  };
}
