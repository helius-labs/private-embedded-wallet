import { describe, expect, it } from "vitest";
import { verifySignedReleasePolicy } from "../verify/release-policy.js";
import { DEVNET_RELEASE } from "./devnet-release.js";

describe("DEVNET_RELEASE", () => {
  it("ships a release policy its authorities signed", () => {
    const { releasePolicy, releaseAuthorities } = DEVNET_RELEASE;
    expect(() =>
      verifySignedReleasePolicy(releasePolicy, releaseAuthorities, BigInt(releasePolicy.policy.validFromMs)),
    ).not.toThrow();
    expect(Object.keys(DEVNET_RELEASE.qosIdentityPcrs).sort()).toEqual(["0", "1", "2", "3"]);
  });
});
