// Unit tests of scripts/release.mjs that need no Turnkey, Docker or enclave:
// node --test scripts/ (the policy phase's tests need `pnpm build:ts` first).
import assert from "node:assert/strict";
import { createECDH, createPublicKey, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { tvcCredentials, turnkeyBootProofs, turnkeyStamp, verifiedReleaseFile, verifyRelease } from "./release.mjs";

function apiKey() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  return { publicKey: ecdh.getPublicKey("hex", "compressed"), privateKey: ecdh.getPrivateKey("hex").padStart(64, "0") };
}

/** Whether `stamp` is `key`'s Turnkey stamp of `body`. */
function stamps(stamp, body, key) {
  const { publicKey, scheme, signature } = JSON.parse(Buffer.from(stamp, "base64url").toString());
  assert.equal(publicKey, key.publicKey);
  assert.equal(scheme, "SIGNATURE_SCHEME_TK_API_P256");
  const point = createECDH("prime256v1");
  point.setPrivateKey(Buffer.from(key.privateKey, "hex"));
  const raw = point.getPublicKey();
  const verifier = createPublicKey({
    format: "jwk",
    key: { kty: "EC", crv: "P-256", x: raw.subarray(1, 33).toString("base64url"), y: raw.subarray(33).toString("base64url") },
  });
  return verify("sha256", Buffer.from(body), verifier, Buffer.from(signature, "hex"));
}

test("a Turnkey stamp is the API key's DER signature over the body", () => {
  const key = apiKey();
  const body = JSON.stringify({ organizationId: "org", ephemeralKey: "04" });
  assert.equal(stamps(turnkeyStamp(body, key), body, key), true);
  assert.equal(stamps(turnkeyStamp(body, key), `${body} `, key), false);
  assert.throws(() => turnkeyStamp(body, { ...key, publicKey: apiKey().publicKey }), /does not match its public key/);
  assert.throws(() => turnkeyStamp(body, { ...key, privateKey: "zz" }), /32-byte private key/);
});

test("the tvc login is the environment's key, or the active organization of tvc's config", () => {
  const dir = mkdtempSync(join(tmpdir(), "release-test-"));
  const key = apiKey();
  writeFileSync(join(dir, "api_key.json"), JSON.stringify({ public_key: key.publicKey, private_key: key.privateKey, curve: "p256" }));
  writeFileSync(
    join(dir, "tvc.config.toml"),
    [
      'version = 1',
      'active_org = "helius"',
      '[orgs.default]',
      'id = "default-org"',
      'api_key_path = "/nowhere.json"',
      '[[orgs.default.operators]]',
      'name = "default"',
      '[orgs.helius]',
      'id = "helius-org"',
      `api_key_path = "${join(dir, "api_key.json")}"`,
      'api_base_url = "https://api.turnkey.example"',
      '[[orgs.helius.operators]]',
      'name = "operator"',
      'id = "not-the-org"',
    ].join("\n"),
  );
  assert.deepEqual(tvcCredentials({ env: {}, configDir: dir }), {
    organizationId: "helius-org",
    apiBaseUrl: "https://api.turnkey.example",
    publicKey: key.publicKey,
    privateKey: key.privateKey,
  });
  const env = { TVC_ORG_ID: "env-org", TVC_API_KEY_PUBLIC: key.publicKey, TVC_API_KEY_PRIVATE: key.privateKey };
  assert.equal(tvcCredentials({ env, configDir: dir }).organizationId, "env-org");
  assert.throws(() => tvcCredentials({ env: { TVC_ORG_ID: "env-org" }, configDir: dir }), /set all of/);
  assert.throws(() => tvcCredentials({ env: {}, configDir: join(dir, "missing") }), /run tvc login/);
});

test("a Boot Proof is looked up in the app's organization with a stamped request", async () => {
  const key = apiKey();
  const credentials = { organizationId: "org", apiBaseUrl: "https://api.turnkey.example", ...key };
  const sent = [];
  const answer = { ephemeralPublicKeyHex: "04", awsAttestationDocB64: "" };
  const lookup = turnkeyBootProofs(credentials, {
    fetch: async (url, init) => {
      sent.push({ url: String(url), init });
      return sent.length === 1 ? Response.json({ bootProof: answer }) : new Response("no", { status: 404 });
    },
  });
  assert.deepEqual(await lookup("04ab"), answer);
  const [{ url, init }] = sent;
  assert.equal(url, "https://api.turnkey.example/public/v1/query/get_boot_proof");
  assert.deepEqual(JSON.parse(init.body), { organizationId: "org", ephemeralKey: "04ab" });
  assert.equal(stamps(init.headers["x-stamp"], init.body, key), true);
  await assert.rejects(lookup("04ab"), /answered the Boot Proof lookup with 404/);
});

const cfg = {
  network: "devnet",
  endpoint: "https://app.example",
  appId: "app",
  securityDomainId: "11".repeat(32),
  quorumKeyId: "quorum",
  quorumKeyEpoch: "1",
  turnkeyTrustRootId: "aws-nitro-root-g1",
  turnkeyProofSchemaVersions: ["turnkey.boot_proof.v1"],
  policyValidityDays: 1,
  qosIdentityPcrs: { 0: "aa".repeat(48), 1: "bb".repeat(48), 2: "cc".repeat(48), 3: "dd".repeat(48) },
};
const info = {
  version: 1,
  network: "devnet",
  security_domain_id: cfg.securityDomainId,
  release_id: "release",
  manifest_digest: "22".repeat(32),
  executable_digest: "33".repeat(32),
  // A QOS public key: the encryption and signing P-256 points.
  quorum_public_key: [apiKey(), apiKey()]
    .map(({ privateKey }) => {
      const point = createECDH("prime256v1");
      point.setPrivateKey(Buffer.from(privateKey, "hex"));
      return point.getPublicKey("hex");
    })
    .join(""),
  quorum_key_id: "quorum",
  quorum_key_epoch: "1",
  ephemeral_public_key: `04${"66".repeat(129)}`,
  supported_operations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"],
  max_encrypted_request_bytes: "262144",
  max_encrypted_response_bytes: "262144",
  proof_type: "spr.tvc.wallet_operation.v1",
};

test("nothing is signed for a replica that does not verify", async () => {
  const signed = [];
  const sign = (policy) => {
    signed.push(policy);
    return { releasePolicy: { policy }, releaseAuthorities: {} };
  };
  await assert.rejects(
    verifiedReleaseFile("release", cfg, info, 1_800_000_000_000, {
      verify: async () => { throw new Error("refused"); },
      sign,
    }),
    /refused/,
  );
  assert.deepEqual(signed, []);
  const file = await verifiedReleaseFile("release", cfg, info, 1_800_000_000_000, { verify: async () => {}, sign });
  assert.equal(signed.length, 1);
  assert.deepEqual(file.qosIdentityPcrs, cfg.qosIdentityPcrs);
  assert.equal(file.releasePolicy.policy.acceptedManifestDigests[0], info.manifest_digest);
});

test("a replica is refused under another trust root, or when it cannot answer the challenge", async () => {
  const requests = [];
  const transport = {
    fetch: async (url) => {
      requests.push(new URL(url).pathname);
      return Response.json({ error: "InvalidRequest" }, { status: 400 });
    },
  };
  const bootProof = async () => assert.fail("no Boot Proof is looked up before the ping verifies");
  await assert.rejects(
    verifyRelease({ ...cfg, turnkeyTrustRootId: "another-root" }, info, { bootProof, transport }),
    /does not verify, so nothing was signed: ReleasePolicyInvalid/,
  );
  assert.deepEqual(requests, []);
  await assert.rejects(
    verifyRelease(cfg, info, { bootProof, transport }),
    /does not verify, so nothing was signed: BootProofUnverified/,
  );
  assert.deepEqual(requests, ["/v1/ping"]);
});
