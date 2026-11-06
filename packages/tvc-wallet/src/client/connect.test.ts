import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { qosDecrypt, qosEncrypt } from "../crypto/qos.js";
import { signP256Message, signP256Prehash } from "../crypto/p256.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type {
  PinnedReleaseAuthorities,
  ReleasePolicy,
  ServiceInfo,
  SignedReleasePolicy,
} from "../protocol/types.js";
import { policySigningDigest } from "../verify/release-policy.js";
import { verifyLiveReplica, type SprEmbeddedWalletConnectionConfig } from "./connection.js";
import type { SprEmbeddedWalletRequestOptions } from "./request.js";
import { createSprEmbeddedWalletSession } from "./session.js";

const verifyBootProofMock = vi.hoisted(() => vi.fn());

vi.mock("../verify/index.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../verify/index.js")>()),
  verifyBootProof: verifyBootProofMock,
}));

/** What the client verifies on first use: a fresh session's connection. */
function verify(config: SprEmbeddedWalletConnectionConfig, options?: SprEmbeddedWalletRequestOptions) {
  return createSprEmbeddedWalletSession(config).context(options);
}

function secret(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

function qosPublic(
  encryptionSecret: Uint8Array,
  signingSecret: Uint8Array
): string {
  return encodeLowerHex(
    Uint8Array.from([
      ...p256.getPublicKey(encryptionSecret, false),
      ...p256.getPublicKey(signingSecret, false),
    ])
  );
}

function oversizedResponse(onPull: () => void): Response {
  const chunk = new Uint8Array(64 * 1024).fill(0x61);
  let pulls = 0;
  return new Response(
    new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        onPull();
        if (pulls > 4_096) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
    }),
    { status: 200 },
  );
}

function connectFixture() {
  const quorumEncryptionSecret = secret("connect-quorum-encryption");
  const quorumSigningSecret = secret("connect-quorum-signing");
  const ephemeralEncryptionSecret = secret("connect-ephemeral-encryption");
  const ephemeralSigningSecret = secret("connect-ephemeral-signing");
  const discoveryEphemeralPublicKey = qosPublic(
    secret("connect-discovery-ephemeral-encryption"),
    secret("connect-discovery-ephemeral-signing")
  );
  const authoritySecret = secret("connect-release-authority");
  const quorumPublicKey = qosPublic(
    quorumEncryptionSecret,
    quorumSigningSecret
  );
  const ephemeralPublicKey = qosPublic(
    ephemeralEncryptionSecret,
    ephemeralSigningSecret
  );
  const manifestDigest = "11".repeat(32);
  const executableDigest = "22".repeat(32);

  const policy: ReleasePolicy = {
    version: 1,
    releaseId: "connect-poc",
    network: "devnet",
    tvcApplicationId: "wallet-dev",
    securityDomainId: "33".repeat(32),
    acceptedManifestDigests: [manifestDigest],
    acceptedExecutableDigests: [executableDigest],
    quorumKeyId: "quorum-connect",
    quorumKeyEpoch: "1",
    quorumPublicKey,
    allowedOperations: ["Bootstrap"],
    maxEncryptedRequestBytes: 262_144,
    maxEncryptedResponseBytes: 262_144,
    turnkeyTrustRootId: "aws-nitro-root-g1",
    turnkeyProofSchemaVersions: ["turnkey.boot_proof.v1"],
    validFromMs: "1700000000000",
    expiresAtMs: "1800000000000",
    revocationEpoch: "0",
  };
  const signedPolicy: SignedReleasePolicy = {
    policy,
    authoritySetId: "connect-authorities",
    signatures: [
      {
        keyId: "connect-authority",
        signature: encodeLowerHex(
          signP256Prehash(authoritySecret, policySigningDigest(policy))
        ),
      },
    ],
  };
  const authorities: PinnedReleaseAuthorities = {
    authoritySetId: "connect-authorities",
    threshold: 1,
    minimumRevocationEpoch: "0",
    keys: [
      {
        keyId: "connect-authority",
        publicKey: encodeLowerHex(p256.getPublicKey(authoritySecret, false)),
      },
    ],
  };
  const info: ServiceInfo = {
    version: 1,
    network: "devnet",
    security_domain_id: policy.securityDomainId,
    release_id: policy.releaseId,
    manifest_digest: manifestDigest,
    executable_digest: executableDigest,
    quorum_public_key: quorumPublicKey,
    quorum_key_id: policy.quorumKeyId,
    quorum_key_epoch: policy.quorumKeyEpoch,
    // /v1/info and /v1/ping may be served by different healthy replicas.
    ephemeral_public_key: discoveryEphemeralPublicKey,
    supported_operations: ["Bootstrap"],
    max_encrypted_request_bytes: "262144",
    max_encrypted_response_bytes: "262144",
    proof_type: "zolana.tvc.wallet_operation.v1",
  };
  const expectedPcrs = {
    0: "44".repeat(48),
    1: "55".repeat(48),
    2: "66".repeat(48),
    3: "77".repeat(48),
  } as const;
  const bootProof = {
    ephemeralPublicKeyHex: ephemeralPublicKey,
    awsAttestationDocB64: "unused-by-mock",
    qosManifestB64: "unused-by-mock",
    qosManifestEnvelopeB64: "unused-by-mock",
    deploymentLabel: "connect-poc",
    enclaveApp: "wallet-dev",
    owner: "zolana",
    createdAt: { seconds: "1750000000", nanos: "0" },
  };

  /** The enclave's ping answer: its ephemeral key signs the decrypted challenge. */
  function pingAnswer(encryptedChallenge: string): string {
    const challengePayload = new TextDecoder().decode(
      qosDecrypt(quorumEncryptionSecret, decodeLowerHex(encryptedChallenge))
    );
    return canonicalizeJsonValue({
      version: 1,
      tvc_app_proof: {
        scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
        public_key: ephemeralPublicKey,
        proof_payload: challengePayload,
        signature: encodeLowerHex(
          signP256Message(
            ephemeralSigningSecret,
            new TextEncoder().encode(challengePayload)
          )
        ),
      },
    });
  }
  return {
    ephemeralPublicKey,
    manifestDigest,
    signedPolicy,
    authorities,
    info,
    expectedPcrs,
    bootProof,
    pingAnswer,
  };
}

describe("verification", () => {
  beforeEach(() =>
    verifyBootProofMock.mockReset().mockResolvedValue(undefined)
  );

  it("runs encrypted QOS ping, resolves the Boot Proof, and holds the verified release", async () => {
    const {
      ephemeralPublicKey,
      manifestDigest,
      signedPolicy,
      authorities,
      info,
      expectedPcrs,
      bootProof,
      pingAnswer,
    } = connectFixture();
    const resolveBootProof = vi.fn().mockResolvedValue(bootProof);
    const config: SprEmbeddedWalletConnectionConfig = {
      backend: {
        kind: "enclave",
        endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
        resolveBootProof,
      },
      network: "devnet",
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: {
        fetch: async (url, init) => {
          if (url.pathname === "/api/tvc/v1/info") {
            return new Response(canonicalizeJsonValue(info), { status: 200 });
          }
          expect(url.pathname).toBe("/api/tvc/v1/ping");
          expect(init?.method).toBe("POST");
          const request = JSON.parse(String(init?.body)) as {
            encrypted_challenge: string;
          };
          return new Response(pingAnswer(request.encrypted_challenge), {
            status: 200,
          });
        },
      },
    };

    await expect(verify(config)).resolves.toMatchObject({
      info: { release_id: "connect-poc", network: "devnet" },
    });
    expect(resolveBootProof).toHaveBeenCalledWith(
      expect.objectContaining({ bootProofLookupKey: ephemeralPublicKey })
    );
    expect(verifyBootProofMock).toHaveBeenCalledWith({
      appProof: expect.objectContaining({ publicKey: ephemeralPublicKey }),
      bootProof,
      allowedManifestSha256: [manifestDigest],
      expectedPcrs,
      nowMs: 1_750_000_000_000n,
    });

    // A resolver may ignore cancellation; no late result may verify or publish a connection.
    const controller = new AbortController();
    let resolveLate!: (value: typeof bootProof) => void;
    const lookupsBefore = resolveBootProof.mock.calls.length;
    const verificationsBefore = verifyBootProofMock.mock.calls.length;
    resolveBootProof.mockImplementationOnce(() => new Promise((resolve) => { resolveLate = resolve; }));
    const pending = verify(config, { signal: controller.signal });
    const rejected = expect(pending).rejects.toThrow("cancelled lookup");
    await vi.waitFor(() => expect(resolveBootProof.mock.calls.length).toBe(lookupsBefore + 1));
    const lookupSignal = resolveBootProof.mock.lastCall?.[0].signal;
    controller.abort(new Error("cancelled lookup"));
    await rejected;
    expect(lookupSignal?.aborted).toBe(true);
    resolveLate(bootProof);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(verifyBootProofMock).toHaveBeenCalledTimes(verificationsBefore);

    let discoveryPulls = 0;
    const oversizedDiscovery = verify({
      backend: {
        kind: "enclave",
        endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
        resolveBootProof,
      },
      network: "devnet",
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: { fetch: async () => oversizedResponse(() => (discoveryPulls += 1)) },
    });
    await expect(oversizedDiscovery).rejects.toThrowError(
      "ResponseTooLarge",
    );
    expect(discoveryPulls).toBeLessThan(4);

    let pingPulls = 0;
    const oversizedPing = verify({
      backend: {
        kind: "enclave",
        endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
        resolveBootProof,
      },
      network: "devnet",
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: {
        fetch: async (url) =>
          url.pathname.endsWith("/v1/info")
            ? new Response(canonicalizeJsonValue(info), { status: 200 })
            : oversizedResponse(() => (pingPulls += 1)),
      },
    });
    await expect(oversizedPing).rejects.toThrowError(
      "ResponseTooLarge",
    );
    expect(pingPulls).toBeLessThan(4);
  });

  it("verifies one gateway session: discovery, the ping and the Boot Proof beside it", async () => {
    const {
      ephemeralPublicKey,
      manifestDigest,
      signedPolicy,
      authorities,
      info,
      expectedPcrs,
      bootProof,
      pingAnswer,
    } = connectFixture();
    const requested: URL[] = [];
    const session = (extra: Record<string, unknown> = {}) =>
      verify({
        backend: {
          kind: "gateway",
          endpoint: new URL("https://gateway.example.invalid/v1/private-wallet?api-key=key"),
        },
        network: "devnet",
        release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
        nowMs: () => 1_750_000_000_000n,
        transport: {
          fetch: async (url, init) => {
            requested.push(url);
            expect(init?.method).toBe("POST");
            const request = JSON.parse(String(init?.body)) as {
              encrypted_challenge: string;
            };
            return new Response(
              JSON.stringify({
                info,
                ping: JSON.parse(pingAnswer(request.encrypted_challenge)),
                bootProof,
                ...extra,
              }),
              { status: 200 }
            );
          },
        },
      });

    await expect(session()).resolves.toMatchObject({
      info: { release_id: "connect-poc" },
    });
    expect(requested.map(String)).toEqual([
      "https://gateway.example.invalid/v1/private-wallet/session?api-key=key",
    ]);
    expect(verifyBootProofMock).toHaveBeenCalledWith({
      appProof: expect.objectContaining({ publicKey: ephemeralPublicKey }),
      bootProof,
      allowedManifestSha256: [manifestDigest],
      expectedPcrs,
      nowMs: 1_750_000_000_000n,
    });

    await expect(session({ policy: {} })).rejects.toMatchObject({
      code: "UnknownJsonField",
    });
  });

  it("reads the clock per use instead of freezing one instant", async () => {
    // A scalar nowMs would pin every freshness check to a single moment for the
    // client's whole life, quietly disabling attestation-age enforcement.
    const seen: bigint[] = [];
    let tick = 1_750_000_000_000n;
    const clock = () => {
      seen.push(tick);
      tick += 1_000n;
      return tick;
    };

    const policyFixture = JSON.parse(
      readFileSync(
        join(
          dirname(fileURLToPath(import.meta.url)),
          "../../../../crates/protocol/fixtures/signed-release-policy.json",
        ),
        "utf8",
      ),
    ) as Record<string, unknown>;

    const verified = verify({
      network: "devnet",
      backend: { kind: "enclave", endpoint: new URL("https://tvc.example.invalid") },
      release: {
        releasePolicy: policyFixture.signed as SignedReleasePolicy,
        releaseAuthorities: policyFixture.authorities as PinnedReleaseAuthorities,
        qosIdentityPcrs: { 0: "00", 1: "00", 2: "00", 3: "00" },
      },
      nowMs: clock,
      transport: { fetch: async () => new Response("{}", { status: 500 }) },
    });

    await expect(verified).rejects.toThrow();
    expect(seen.length).toBeGreaterThan(0);
  });
});

describe("the client's network", () => {
  it("refuses a release for another network before it fetches anything", async () => {
    const { signedPolicy, authorities, expectedPcrs } = connectFixture();
    const fetch = vi.fn();
    const verified = verify({
      network: "mainnet",
      backend: { kind: "gateway", endpoint: new URL("https://gateway.example.invalid/v1/private-wallet") },
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: { fetch },
    });
    await expect(verified).rejects.toMatchObject({ code: "NetworkMismatch" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses discovery for another network than the release's", async () => {
    const { signedPolicy, authorities, info, expectedPcrs, bootProof, pingAnswer } = connectFixture();
    const verified = verify({
      network: "devnet",
      backend: { kind: "gateway", endpoint: new URL("https://gateway.example.invalid/v1/private-wallet") },
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: {
        fetch: async (_url, init) => {
          const { encrypted_challenge } = JSON.parse(String(init?.body)) as { encrypted_challenge: string };
          return Response.json({
            info: { ...info, network: "mainnet" },
            ping: JSON.parse(pingAnswer(encrypted_challenge)),
            bootProof,
          });
        },
      },
    });
    await expect(verified).rejects.toMatchObject({ code: "NetworkMismatch" });
  });
});

describe("a live replica, before its release is signed", () => {
  beforeEach(() => verifyBootProofMock.mockReset().mockResolvedValue(undefined));

  function enclave(answer: (encryptedChallenge: string) => string) {
    const fetch = vi.fn(async (url: URL, init?: RequestInit) => {
      expect(url.pathname).toBe("/v1/ping");
      const request = JSON.parse(String(init?.body)) as { encrypted_challenge: string };
      try {
        return new Response(answer(request.encrypted_challenge), { status: 200 });
      } catch {
        // A challenge sealed to a key the replica does not hold.
        return new Response('{"error":"InvalidRequest"}', { status: 400 });
      }
    });
    return { fetch };
  }

  it("answers the ping under the Quorum key info names, and its Boot Proof attests info's manifest", async () => {
    const { ephemeralPublicKey, manifestDigest, info, expectedPcrs, bootProof, pingAnswer } = connectFixture();
    const lookup = vi.fn().mockResolvedValue(bootProof);
    await verifyLiveReplica({
      endpoint: new URL("https://app.example"),
      info,
      qosIdentityPcrs: expectedPcrs,
      turnkeyTrustRootId: "aws-nitro-root-g1",
      bootProof: lookup,
      transport: enclave(pingAnswer),
      nowMs: 1_750_000_000_000n,
    });
    expect(lookup).toHaveBeenCalledWith(ephemeralPublicKey, undefined);
    expect(verifyBootProofMock).toHaveBeenCalledWith({
      appProof: expect.objectContaining({ publicKey: ephemeralPublicKey }),
      bootProof,
      allowedManifestSha256: [manifestDigest],
      expectedPcrs,
      nowMs: 1_750_000_000_000n,
    });
  });

  it("is refused when another key answers, the Boot Proof fails, or the trust root is not the pinned one", async () => {
    const { info, expectedPcrs, bootProof, pingAnswer } = connectFixture();
    const input = {
      endpoint: new URL("https://app.example"),
      info,
      qosIdentityPcrs: expectedPcrs,
      turnkeyTrustRootId: "aws-nitro-root-g1",
      bootProof: vi.fn().mockResolvedValue(bootProof),
      transport: enclave(pingAnswer),
    };
    // A Quorum key the replica does not hold: it cannot read the challenge.
    const { info: otherRelease } = connectFixture();
    const otherQuorum = qosPublic(secret("another-quorum-encryption"), secret("another-quorum-signing"));
    await expect(
      verifyLiveReplica({ ...input, info: { ...otherRelease, quorum_public_key: otherQuorum } }),
    ).rejects.toMatchObject({ code: "BootProofUnverified", status: 400 });
    // An answer to another challenge.
    const replayed = enclave(() => pingAnswer(encodeLowerHex(qosEncrypt(
      p256.getPublicKey(secret("connect-quorum-encryption"), false),
      new TextEncoder().encode("another challenge"),
    ))));
    await expect(verifyLiveReplica({ ...input, transport: replayed })).rejects.toMatchObject({
      code: "TurnkeyEvidenceInvalid",
    });
    verifyBootProofMock.mockRejectedValueOnce(new Error("BootProofUnverified"));
    await expect(verifyLiveReplica(input)).rejects.toThrow("BootProofUnverified");
    const fetch = vi.fn();
    await expect(
      verifyLiveReplica({ ...input, turnkeyTrustRootId: "another-root", transport: { fetch } }),
    ).rejects.toMatchObject({ code: "ReleasePolicyInvalid" });
    expect(fetch).not.toHaveBeenCalled();
  });
});
