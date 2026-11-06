// THE SINGLE TURNKEY SEAM for @heliuslabs/spr-embedded-wallet.
//
// @turnkey/* may only be imported from this file. The composite verifier uses
// Turnkey's AWS Nitro X.509 chain helper, then applies the Zolana release-policy
// and PCR checks outside this seam.
//
// Why this does not just call `turnkeyCrypto.verify(appProof, bootProof)`,
// which exists and looks like it would do the job — @turnkey/crypto's own
// docstring on it says:
//
//   "WARNING: This is not full verification of a Turnkey enclave. It does not
//    verify the enclave identity or image measurements [...] Any party with an
//    AWS account can run their own Nitro enclave and produce attestations that
//    pass this check. For full verification, callers must additionally pin and
//    verify the expected PCR measurements and manifest content."
//
// `verifyBootProof` is that additional verification: pinned PCR0-3, the PCR17
// live-manifest commitment, and the manifest digest checked against the signed
// release policy. Three further deliberate divergences from the reference:
//
//   - Reference `verify()` passes `appProof.proofPayload.timestampMs` as the
//     certificate-chain validation time. We pass the verifier's own clock, so
//     no attacker-supplied value decides whether the chain authenticating that
//     same attacker's document was valid.
//   - Reference `verify()` recomputes the manifest digest as SHA-256 over the
//     Borsh bytes in `qosManifestB64`. QOS commits
//     `VersionedManifest::manifest_hash()`, which is not that, so we compare
//     `user_data` against the policy's pinned digests instead.
//   - `verifyCoseSign1Sig` is also exported by @turnkey/crypto, but it routes
//     the Sig_structure through `cbor-js` (an unmaintained 2015 package that
//     @turnkey/crypto still depends on). Our COSE check uses the strict
//     deterministic codec in ./cbor.ts so that no attacker-controlled CBOR is
//     parsed by that library on our path.
//
// The AWS Nitro root below is pinned here rather than imported from
// @turnkey/crypto: a trust root is something you pin yourself, out of band.
// It has been verified byte-identical to `constants.AWS_ROOT_CERT_PEM`.
//
// This is still not a production verifier: production release-policy
// distribution and Turnkey `decisionContextDigest` binding are unavailable.

import * as turnkeyCrypto from "@turnkey/crypto";
import type { v1AppProof, v1BootProof } from "@turnkey/sdk-types";
import * as x509 from "@peculiar/x509";

import { encodeCoseSigStructure } from "./cbor.js";

const AWS_NITRO_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

export const TURNKEY_TS_PROOF_PROFILE = {
  crypto: "2.11.3",
  sdkTypes: "1.5.1",
  productionVerifier: false,
  referenceBootProofVerifier: true,
  reason:
    "development composite verifier; production release-policy distribution and decisionContextDigest binding remain unavailable",
} as const;

export type CoseSign1 = {
  readonly protectedHeaders: Uint8Array;
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
};

export type TurnkeyAppProofWire = v1AppProof;
export type TurnkeyBootProofWire = v1BootProof;

export async function verifyTurnkeyAwsAttestation(
  coseSign1: CoseSign1,
  certificate: Uint8Array,
  cabundle: Uint8Array[],
  timestampMs: number
): Promise<void> {
  await verifyCoseSign1Signature(coseSign1, certificate);
  await turnkeyCrypto.verifyCertificateChain(
    cabundle,
    AWS_NITRO_ROOT_CERT_PEM,
    certificate,
    timestampMs
  );
}

async function verifyCoseSign1Signature(
  coseSign1: CoseSign1,
  leaf: Uint8Array
): Promise<void> {
  // ES384 is fixed by this verifier rather than read from the protected
  // header, so a document cannot negotiate a weaker algorithm.
  const tbs = encodeCoseSigStructure(
    coseSign1.protectedHeaders,
    new Uint8Array(0),
    coseSign1.payload
  );
  const cryptoInstance = await turnkeyCrypto.getCryptoInstance();
  const leafCertificate = new x509.X509Certificate(exactArrayBuffer(leaf));
  const publicKey = await cryptoInstance.subtle.importKey(
    "spki",
    leafCertificate.publicKey.rawData,
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"]
  );
  const valid = await cryptoInstance.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    publicKey,
    exactArrayBuffer(coseSign1.signature),
    exactArrayBuffer(tbs)
  );
  if (!valid) throw new Error("COSE_Sign1 ES384 verification failed");
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

export function assertNotProductionVerifier(): void {
  if (TURNKEY_TS_PROOF_PROFILE.productionVerifier) {
    throw new Error("production verifier flag must remain false");
  }
}
