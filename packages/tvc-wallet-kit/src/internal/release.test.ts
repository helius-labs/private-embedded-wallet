import { describe, expect, it } from "vitest";
import {
  bindDiscoveryToPolicy,
  verifySignedReleasePolicy,
} from "@zolana/tvc-wallet";
import type { ServiceInfo } from "@zolana/tvc-wallet/protocol";
import {
  PRIVATE_WALLET_QOS_IDENTITY_PCRS,
  PRIVATE_WALLET_RELEASE_AUTHORITIES,
  PRIVATE_WALLET_RELEASE_POLICY,
} from "./release";

describe("private wallet release trust material", () => {
  it("verifies the independent signature at the real clock", () => {
    expect(() =>
      verifySignedReleasePolicy(
        PRIVATE_WALLET_RELEASE_POLICY,
        PRIVATE_WALLET_RELEASE_AUTHORITIES,
        BigInt(Date.now()),
      ),
    ).not.toThrow();
  });

  it("binds all five key operations to discovery", () => {
    const policy = PRIVATE_WALLET_RELEASE_POLICY.policy;
    expect(policy.allowedOperations).toEqual([
      "Bootstrap",
      "Decrypt",
      "Derive",
      "TransactionKeys",
      "Prove",
    ]);
    const info = {
      version: 1,
      environment: "development",
      security_domain_id: policy.securityDomainId,
      release_id: policy.releaseId,
      manifest_digest: policy.acceptedManifestDigests[0]!,
      executable_digest: policy.acceptedExecutableDigests[0]!,
      quorum_public_key: policy.quorumPublicKey,
      quorum_key_id: policy.quorumKeyId,
      quorum_key_epoch: policy.quorumKeyEpoch,
      ephemeral_public_key: `04${"11".repeat(64)}04${"22".repeat(64)}`,
      supported_operations: [...policy.allowedOperations],
      max_encrypted_request_bytes: String(policy.maxEncryptedRequestBytes),
      max_encrypted_response_bytes: String(policy.maxEncryptedResponseBytes),
      proof_type: "zolana.tvc.wallet_operation.v1",
      boot_proof_lookup_key: `04${"11".repeat(64)}04${"22".repeat(64)}`,
    } satisfies ServiceInfo;

    expect(() =>
      bindDiscoveryToPolicy(info, PRIVATE_WALLET_RELEASE_POLICY),
    ).not.toThrow();
    expect(Object.keys(PRIVATE_WALLET_QOS_IDENTITY_PCRS)).toEqual([
      "0",
      "1",
      "2",
      "3",
    ]);
  });
});
