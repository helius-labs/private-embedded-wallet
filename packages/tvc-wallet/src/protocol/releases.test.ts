import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";

import { assertExactObjectKeys } from "../client/http.js";
import { signP256Prehash } from "../crypto/p256.js";
import { policySigningDigest, verifySignedReleasePolicy } from "../verify/release-policy.js";
import { encodeLowerHex } from "./hex.js";
import { RELEASES, releaseFor, type ReleaseTrust } from "./releases.js";
import type { Network, ReleasePolicy } from "./types.js";

const RELEASES_DIR = join(dirname(fileURLToPath(import.meta.url)), "../releases");
const NETWORKS: readonly Network[] = ["devnet", "mainnet"];
const POLICY_KEYS = [
  "version",
  "releaseId",
  "network",
  "tvcApplicationId",
  "securityDomainId",
  "acceptedManifestDigests",
  "acceptedExecutableDigests",
  "quorumKeyId",
  "quorumKeyEpoch",
  "quorumPublicKey",
  "allowedOperations",
  "maxEncryptedRequestBytes",
  "maxEncryptedResponseBytes",
  "turnkeyTrustRootId",
  "turnkeyProofSchemaVersions",
  "validFromMs",
  "expiresAtMs",
  "revocationEpoch",
] as const;

/**
 * A pinned release file for `network`, as a client takes it: exactly the
 * three parts, a policy of exactly the protocol's fields signed by the pinned
 * authorities for `network` and in force at `nowMs`, and four PCRs.
 */
function verifyReleaseFile(value: unknown, network: Network, nowMs: bigint): ReleaseTrust {
  assertExactObjectKeys(value, ["releasePolicy", "releaseAuthorities", "qosIdentityPcrs"], "ReleasePolicyInvalid");
  const release = value as ReleaseTrust;
  assertExactObjectKeys(release.releasePolicy, ["policy", "authoritySetId", "signatures"], "ReleasePolicyInvalid");
  assertExactObjectKeys(release.releasePolicy.policy, POLICY_KEYS, "ReleasePolicyInvalid");
  verifySignedReleasePolicy(release.releasePolicy, release.releaseAuthorities, network, nowMs);
  assertExactObjectKeys(release.qosIdentityPcrs, ["0", "1", "2", "3"], "ReleasePolicyInvalid");
  for (const pcr of Object.values(release.qosIdentityPcrs)) expect(pcr).toMatch(/^[0-9a-f]{96}$/);
  return release;
}

describe("the committed release files", () => {
  const files = readdirSync(RELEASES_DIR).sort();

  it("are one per network", () => {
    expect(files).toEqual(NETWORKS.map((network) => `${network}.json`));
  });

  it.each(NETWORKS)("%s pins nothing, or a release that verifies for it", (network) => {
    const pinned = JSON.parse(readFileSync(join(RELEASES_DIR, `${network}.json`), "utf8")) as unknown;
    if (pinned === null) {
      expect(Object.hasOwn(RELEASES, network)).toBe(false);
      expect(() => releaseFor(network)).toThrowError(/ReleaseNotPinned/);
      return;
    }
    const release = verifyReleaseFile(pinned, network, BigInt(Date.now()));
    expect(release.releasePolicy.policy.network).toBe(network);
    expect(releaseFor(network)).toEqual(pinned);
  });
});

describe("a release file", () => {
  const authority = p256.utils.randomPrivateKey();
  const policy: ReleasePolicy = {
    version: 1,
    releaseId: "private-wallet-devnet-test",
    network: "devnet",
    tvcApplicationId: "app",
    securityDomainId: "33".repeat(32),
    acceptedManifestDigests: ["11".repeat(32)],
    acceptedExecutableDigests: ["22".repeat(32)],
    quorumKeyId: "quorum",
    quorumKeyEpoch: "1",
    quorumPublicKey: "04".repeat(130),
    allowedOperations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"],
    maxEncryptedRequestBytes: 262_144,
    maxEncryptedResponseBytes: 262_144,
    turnkeyTrustRootId: "aws-nitro-root-g1",
    turnkeyProofSchemaVersions: ["turnkey.boot_proof.v1"],
    validFromMs: "1700000000000",
    expiresAtMs: "1900000000000",
    revocationEpoch: "0",
  };
  const file = (signed: ReleasePolicy, extra: Record<string, unknown> = {}) => ({
    releasePolicy: {
      policy: signed,
      authoritySetId: "set",
      signatures: [{ keyId: "authority", signature: encodeLowerHex(signP256Prehash(authority, policySigningDigest(signed))) }],
    },
    releaseAuthorities: {
      authoritySetId: "set",
      threshold: 1,
      keys: [{ keyId: "authority", publicKey: encodeLowerHex(p256.getPublicKey(authority, false)) }],
      minimumRevocationEpoch: "0",
    },
    qosIdentityPcrs: { 0: "aa".repeat(48), 1: "bb".repeat(48), 2: "cc".repeat(48), 3: "dd".repeat(48) },
    ...extra,
  });
  const now = 1_800_000_000_000n;

  it("verifies for the network it names and no other", () => {
    expect(verifyReleaseFile(file(policy), "devnet", now).releasePolicy.policy).toEqual(policy);
    expect(() => verifyReleaseFile(file(policy), "mainnet", now)).toThrowError(/NetworkMismatch/);
  });

  it("is refused tampered, expired, in another shape, or with a field the protocol does not have", () => {
    const tampered = file(policy);
    tampered.releasePolicy.policy = { ...policy, releaseId: "other" };
    expect(() => verifyReleaseFile(tampered, "devnet", now)).toThrowError(/InvalidSignature/);
    expect(() => verifyReleaseFile(file(policy), "devnet", 1_950_000_000_000n)).toThrowError(/ExpiredRequest/);
    expect(() => verifyReleaseFile(file(policy, { extra: true }), "devnet", now)).toThrowError(/UnknownJsonField/);
    const withEnvironment = { ...policy, environment: "development" } as unknown as ReleasePolicy;
    expect(() => verifyReleaseFile(file(withEnvironment), "devnet", now)).toThrowError(/UnknownJsonField/);
  });
});
