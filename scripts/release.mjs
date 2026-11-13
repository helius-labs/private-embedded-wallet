#!/usr/bin/env node
// Releases one enclave application of one network in three phases, each
// resumable on its own:
//
//   build   reads the /tvc_app digest from the network's image that
//           publish-enclave-image pushed and writes the deployment
//           descriptor
//   deploy  creates the TVC deployment, approves and provisions it for every
//           operator, makes it live, and waits for /v1/info to serve it
//   policy  verifies the live replica's Boot Proof as a client would (the
//           pinned QOS PCRs, the manifest digest and Quorum key /v1/info
//           reports, the Turnkey trust root), then assembles the release
//           policy from /v1/info, signs it with a one-time authority key, and
//           pins it in tvc-wallet: src/releases/<network>.json for the
//           privacy wallet, the file tvc-gateway reads too
//
//   node scripts/release.mjs <build|deploy|policy|all> <release-id>
//     --network <devnet|mainnet> [--app <privacy-wallet|decryption-service>]
//     [--image <reference>] [--unattended] [--prune-deployments]
//     [--operator-seeds <dir> --quorum-key-metadata <file>]
//
// Turnkey is driven through the `tvc` CLI and its active login; the policy
// phase reads that login's API key to fetch the Boot Proof, and verifies it
// with tvc-wallet's build (packages/tvc-wallet/dist). Approvals are
// interactive: the CLI shows the QOS manifest for each operator to confirm.
// --unattended approves without that review, on devnet only.
// --prune-deployments deletes the oldest deployments that are neither live nor
// this release's until it fits under Turnkey's cap. With a local Quorum key,
// --operator-seeds holds the key files of the operators who act here
// (`operator-<n>.seed` for the n-th of `operatorIds`) and
// --quorum-key-metadata the encrypted shares. The constants are in
// apps/<app>/deploy/release.json, shared at the top and per network under
// `networks`; each network's deployment files are in
// apps/<app>/deploy/<network>/.

import { execFileSync, spawnSync } from "node:child_process";
import { createECDH, createPrivateKey, sign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const ROOT = resolve(import.meta.dirname, "..");
const NETWORKS = ["devnet", "mainnet"];
/** `API_VERSION` in crates/protocol/src/constants.rs: the release policy and `/v1/info` version. */
const API_VERSION = 1;
/**
 * Each enclave application: its operations, in the order the enclave
 * advertises them and clients compare them, and its release pins in tvc-wallet.
 */
const APPS = {
  "privacy-wallet": {
    operations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"],
    pins: "packages/tvc-wallet/src/releases",
  },
  "decryption-service": {
    operations: ["ServicePublicKeys", "ServiceDecrypt"],
    pins: "packages/tvc-wallet/src/decryption-service/releases",
  },
};
/** A `cfg` without an `app` is the privacy wallet's. */
const appOf = (cfg) => cfg.app ?? "privacy-wallet";
const deployDir = (cfg) => join(ROOT, "apps", appOf(cfg), "deploy");
const HEX = (bytes) => new RegExp(`^[0-9a-f]{${2 * bytes}}$`);
const WAIT_MS = 20 * 60_000;
/** Turnkey's cap on deployable deployments per TVC app. */
const DEPLOYABLE_LIMIT = 3;
/** tvc-wallet's built `./testing` entry, whose `verifyLiveReplica` checks the replica before the policy is signed. */
const CLIENT_TESTING = join(ROOT, "packages/tvc-wallet/dist/testing.js");
const TURNKEY_API = "https://api.turnkey.com";

/** The network's release pin in tvc-wallet. */
const pinPath = (cfg) => join(ROOT, APPS[appOf(cfg)].pins, `${cfg.network}.json`);
const descriptorPath = (cfg, releaseId) => join(deployDir(cfg), cfg.network, `${appOf(cfg)}-${releaseId}.deployment.json`);
const recordPath = (cfg, releaseId) => join(deployDir(cfg), cfg.network, `${appOf(cfg)}-${releaseId}.deploy.json`);

class ReleaseError extends Error {}

function fail(message) {
  throw new ReleaseError(message);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`${path}: ${error.message}`);
  }
}

function writeJson(path, value) {
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${relative(ROOT, path)}`);
}

/** Runs a command on the terminal, for the prompts of an interactive approval. */
function run(command, args) {
  console.log(`$ ${command} ${args.join(" ")}`);
  if (spawnSync(command, args, { stdio: "inherit", cwd: ROOT }).status !== 0) fail(`${command} ${args[0]} failed`);
}

/** Runs a command and returns its stdout. */
function capture(command, args) {
  console.log(`$ ${command} ${args.join(" ")}`);
  try {
    return execFileSync(command, args, { encoding: "utf8", cwd: ROOT, stdio: ["ignore", "pipe", "inherit"] });
  } catch (error) {
    // tvc reports its errors as JSON on stdout.
    if (error.stdout) console.error(String(error.stdout).trim());
    fail(`${command} ${args.slice(0, 2).join(" ")} failed`);
  }
}

/** A `tvc` command's answer: the last line of its newline-delimited JSON. */
const tvc = (...args) => JSON.parse(capture("tvc", [...args, "--message-format", "json"]).trim().split("\n").at(-1));

const tvcSucceeds = (...args) => spawnSync("tvc", [...args, "--message-format", "json"], { stdio: "ignore" }).status === 0;

async function waitFor(label, ready) {
  const deadline = Date.now() + WAIT_MS;
  while (!(await ready())) {
    if (Date.now() > deadline) fail(`timed out waiting for ${label}`);
    console.log(`waiting for ${label}`);
    await sleep(15_000);
  }
}

/**
 * The shared constants of release.json with those of `network` on top, and
 * `network` itself. A network without an entry has no Turnkey app yet.
 */
function config(network, app) {
  const { networks, ...shared } = readJson(join(deployDir({ app }), "release.json"));
  for (const key of ["imageRepository", "qosVersion", "turnkeyTrustRootId"]) {
    if (typeof shared[key] !== "string" || shared[key] === "") fail(`release.json: ${key} is required`);
  }
  if (!Array.isArray(shared.turnkeyProofSchemaVersions) || shared.turnkeyProofSchemaVersions.length === 0) {
    fail("release.json: turnkeyProofSchemaVersions is required");
  }
  if (!Number.isSafeInteger(shared.policyValidityDays) || shared.policyValidityDays < 1) {
    fail("release.json: policyValidityDays must be a positive whole number");
  }
  for (const index of ["0", "1", "2", "3"]) {
    if (!HEX(48).test(shared.qosIdentityPcrs?.[index] ?? "")) fail(`release.json: qosIdentityPcrs.${index} must be 48-byte hex`);
  }
  if (typeof networks !== "object" || networks === null || !Object.hasOwn(networks, network)) {
    fail(`release.json has no networks.${network}: add the ${network} Turnkey app, its Quorum key and operators first`);
  }
  const net = networks[network];
  if (typeof net !== "object" || net === null) fail(`release.json: networks.${network} must be an object`);
  for (const key of ["appId", "endpoint", "securityDomainId", "quorumKeyId", "quorumKeyEpoch"]) {
    if (typeof net[key] !== "string" || net[key] === "") fail(`release.json: networks.${network}.${key} is required`);
  }
  if (!Array.isArray(net.operatorIds) || net.operatorIds.length === 0) {
    fail(`release.json: networks.${network}.operatorIds is required`);
  }
  return { ...shared, ...net, network, app };
}

function build(releaseId, cfg, image) {
  if (!image) fail("build needs --image, the reference publish-enclave-image reports");
  // The publish workflow tags each image with its application and the network it was built for.
  const tag = `${cfg.imageRepository}:${appOf(cfg)}-${cfg.network}-`;
  if (!image.startsWith(tag) || !/^[^@]+@sha256:[0-9a-f]{64}$/.test(image)) {
    fail(`--image must be ${tag}<commit>@sha256:<digest>, the ${cfg.network} image publish-enclave-image reports`);
  }
  const pivotDigest = capture("docker", ["run", "--rm", "--platform", "linux/amd64", "--entrypoint", "sha256sum", image, "/tvc_app"]).split(" ")[0];
  if (!HEX(32).test(pivotDigest)) fail(`could not read the /tvc_app digest: ${pivotDigest}`);
  writeJson(descriptorPath(cfg, releaseId), {
    appId: cfg.appId,
    qosVersion: cfg.qosVersion,
    pivotContainerImageUrl: image,
    pivotPath: "/tvc_app",
    pivotArgs: [
      "--host", "0.0.0.0",
      "--port", "3000",
      "--security-domain-id", cfg.securityDomainId,
      "--release-id", releaseId,
      "--quorum-key-id", cfg.quorumKeyId,
      "--quorum-key-epoch", cfg.quorumKeyEpoch,
    ],
    expectedPivotDigest: pivotDigest,
    dangerousDeployDebugMode: false,
    healthCheckType: "TVC_HEALTH_CHECK_TYPE_HTTP",
    healthCheckPort: 3000,
    publicIngressPort: 3000,
  });
}

function liveDeploymentId(cfg) {
  const app = tvc("app", "list").apps.find(({ id }) => id === cfg.appId);
  if (!app) fail(`app ${cfg.appId} is not in the organization tvc is logged in to`);
  return app.liveDeploymentId;
}

/** Deletes the oldest deployments that are neither live nor `deployId` until `deployId` fits under the cap. */
function pruneDeployments(cfg, deployId) {
  const keep = new Set([liveDeploymentId(cfg), deployId].filter(Boolean));
  const others = tvc("app", "status", "--app-id", cfg.appId)
    .deployments.filter(({ deploymentId }) => !keep.has(deploymentId))
    .map(({ deploymentId }) => tvc("deploy", "status", "--deploy-id", deploymentId))
    .sort((a, b) => Number(a.createdAt.seconds) - Number(b.createdAt.seconds));
  while (others.length + keep.size > DEPLOYABLE_LIMIT) {
    const { deploymentId, pivotContainer } = others.shift();
    console.log(`deleting deployment ${deploymentId} (${pivotContainer.args[pivotContainer.args.indexOf("--release-id") + 1]})`);
    tvc("deploy", "delete", "--deploy-id", deploymentId);
  }
}

async function fetchInfo(endpoint) {
  const response = await fetch(new URL("v1/info", `${endpoint}/`));
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/** Waits until the endpoint serves this release, and returns its /v1/info. */
async function awaitRelease(releaseId, cfg) {
  const { expectedPivotDigest } = readJson(descriptorPath(cfg, releaseId));
  let info;
  await waitFor(`${cfg.endpoint} to serve ${releaseId}`, async () => {
    info = await fetchInfo(cfg.endpoint).catch((error) => ({ error: error.message }));
    return info.release_id === releaseId && info.executable_digest === expectedPivotDigest;
  });
  return info;
}

/**
 * Re-encrypts one operator's share of a local Quorum key to the deployment's
 * enclave, once tvc has verified its attestation, and posts it.
 */
function postLocalShare(deployId, operatorId, { seed, metadata }) {
  const scratch = mkdtempSync(join(tmpdir(), "spr-tvc-share-"));
  try {
    const bundle = join(scratch, "bundle.json");
    const share = join(scratch, "share.json");
    tvc("deploy", "provisioning-details", "--deploy-id", deployId, "--provision-bundle-out", bundle);
    tvc("keys", "re-encrypt-local-share", "--quorum-key-metadata", metadata, "--provision-bundle", bundle,
      "--operator-seed-path", seed, "--re-encrypted-out", share);
    tvc("deploy", "post-share", "--re-encrypted-share", share, "--share-operator-id", operatorId);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** The deployment record is the phase's progress: a re-run continues where the last one stopped. */
async function deploy(releaseId, cfg, { unattended, prune, seeds, metadata }) {
  const descriptor = descriptorPath(cfg, releaseId);
  if (!existsSync(descriptor)) fail(`no ${relative(ROOT, descriptor)}: run build first`);
  const path = recordPath(cfg, releaseId);
  const record = existsSync(path)
    ? readJson(path)
    : { deployId: tvc("deploy", "create", "--config-file", descriptor).deploymentId, approved: [], provisioned: [], live: false };
  const save = () => writeJson(path, record);
  save();
  const { deployId } = record;
  if (prune) pruneDeployments(cfg, deployId);

  // With a local Quorum key, the operators whose key files are here act; a threshold of them is enough.
  const seedOf = (operatorId) => join(seeds, `operator-${cfg.operatorIds.indexOf(operatorId) + 1}.seed`);
  const operatorIds = seeds ? cfg.operatorIds.filter((id) => existsSync(seedOf(id))) : cfg.operatorIds;
  if (operatorIds.length === 0) fail(`no operator-<n>.seed in ${seeds}`);

  for (const operatorId of operatorIds.filter((id) => !record.approved.includes(id))) {
    const approve = ["deploy", "approve", "--deploy-id", deployId,
      ...(seeds ? ["--operator-seed-path", seedOf(operatorId)] : ["--operator-id", operatorId])];
    if (unattended) tvc(...approve, "--dangerous-skip-interactive");
    else run("tvc", approve);
    record.approved.push(operatorId);
    save();
  }

  // Provisioning hands each operator's share of the Quorum key to the
  // enclave, once its attestation is up and tvc has verified it.
  const unprovisioned = operatorIds.filter((id) => !record.provisioned.includes(id));
  if (unprovisioned.length > 0) {
    await waitFor("the provisioning attestation", () => tvcSucceeds("deploy", "provisioning-details", "--deploy-id", deployId));
  }
  for (const operatorId of unprovisioned) {
    if (seeds) postLocalShare(deployId, operatorId, { seed: seedOf(operatorId), metadata });
    else tvc("deploy", "provision", "--deploy-id", deployId, "--operator-id", operatorId);
    record.provisioned.push(operatorId);
    save();
  }

  if (!record.live) {
    // Turnkey answers the status of a deployment that is still starting with an error at times.
    await waitFor("a ready replica", () => {
      try {
        return tvc("deploy", "get-status", "--deploy-id", deployId).replicas?.ready > 0;
      } catch (error) {
        if (error instanceof ReleaseError) return false;
        throw error;
      }
    });
    // An app's first deployment is live once healthy, and Turnkey refuses to set it live again.
    if (liveDeploymentId(cfg) !== deployId) tvc("app", "set-live-deploy", "--deploy-id", deployId);
    record.live = true;
    save();
  }
  await awaitRelease(releaseId, cfg);
}

/**
 * The unsigned release policy for `releaseId` as the enclave at `cfg.endpoint`
 * serves it (`info`, its /v1/info), checked against the release constants:
 * the shape `ReleasePolicy` in crates/protocol takes.
 */
export function releasePolicy(releaseId, cfg, info, now) {
  const expect = (field, expected) => {
    if (info[field] !== expected) fail(`/v1/info ${field} is ${info[field]}, expected ${expected}`);
  };
  expect("version", API_VERSION);
  expect("network", cfg.network);
  expect("security_domain_id", cfg.securityDomainId);
  expect("quorum_key_id", cfg.quorumKeyId);
  expect("quorum_key_epoch", cfg.quorumKeyEpoch);
  if (!HEX(32).test(info.manifest_digest)) fail("/v1/info manifest_digest is not 32-byte hex");
  if (!HEX(32).test(info.executable_digest)) fail("/v1/info executable_digest is not 32-byte hex");
  if (!HEX(130).test(info.quorum_public_key)) fail("/v1/info quorum_public_key is not a QOS public key");
  const { operations } = APPS[appOf(cfg)];
  if (!Array.isArray(info.supported_operations) || info.supported_operations.join() !== operations.join()) {
    fail(`/v1/info supported_operations are ${info.supported_operations}, expected ${operations.join(", ")}`);
  }
  return {
    version: API_VERSION,
    releaseId,
    network: cfg.network,
    tvcApplicationId: cfg.appId,
    securityDomainId: cfg.securityDomainId,
    acceptedManifestDigests: [info.manifest_digest],
    acceptedExecutableDigests: [info.executable_digest],
    quorumKeyId: cfg.quorumKeyId,
    quorumKeyEpoch: cfg.quorumKeyEpoch,
    quorumPublicKey: info.quorum_public_key,
    allowedOperations: operations,
    maxEncryptedRequestBytes: Number(info.max_encrypted_request_bytes),
    maxEncryptedResponseBytes: Number(info.max_encrypted_response_bytes),
    turnkeyTrustRootId: cfg.turnkeyTrustRootId,
    turnkeyProofSchemaVersions: cfg.turnkeyProofSchemaVersions,
    revocationEpoch: "0",
    validFromMs: String(now),
    expiresAtMs: String(now + cfg.policyValidityDays * 86_400_000),
  };
}

/**
 * Signs `policy` under a fresh authority set with
 * `cargo run -p zolana-tvc-protocol --example sign-release-policy`, which
 * verifies the result as `verify_signed_release_policy` does for the policy's
 * network before it answers. The authority key is generated inside that call,
 * used once, and gone when it exits; only the signed policy and the public
 * half come back, as `{releasePolicy, releaseAuthorities}`.
 */
export function signReleasePolicy(policy, authoritySetId) {
  const scratch = mkdtempSync(join(tmpdir(), "zolana-tvc-release-"));
  try {
    writeFileSync(join(scratch, "policy.json"), JSON.stringify(policy));
    const args = ["run", "-q", "-p", "zolana-tvc-protocol", "--example", "sign-release-policy", "--", join(scratch, "policy.json"), authoritySetId];
    return JSON.parse(capture("cargo", args));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/**
 * The Turnkey API key the `tvc` CLI acts with, and its organization, which
 * holds the TVC app: `TVC_ORG_ID`, `TVC_API_KEY_PUBLIC` and
 * `TVC_API_KEY_PRIVATE` when set, as tvc reads them, else the active
 * organization of tvc's config file.
 */
export function tvcCredentials({ env = process.env, configDir = join(homedir(), ".config/turnkey") } = {}) {
  const named = [env.TVC_ORG_ID, env.TVC_API_KEY_PUBLIC, env.TVC_API_KEY_PRIVATE];
  if (named.some(Boolean)) {
    if (!named.every(Boolean)) fail("set all of TVC_ORG_ID, TVC_API_KEY_PUBLIC and TVC_API_KEY_PRIVATE, or none");
    const [organizationId, publicKey, privateKey] = named;
    return { organizationId, apiBaseUrl: TURNKEY_API, publicKey, privateKey };
  }
  const path = join(configDir, "tvc.config.toml");
  if (!existsSync(path)) fail(`no ${path}: run tvc login, or set TVC_ORG_ID, TVC_API_KEY_PUBLIC and TVC_API_KEY_PRIVATE`);
  const config = readFileSync(path, "utf8");
  const active = /^active_org\s*=\s*"([^"]+)"/m.exec(config)?.[1];
  if (!active) fail(`${path} names no active_org`);
  // The [orgs.<active>] table, up to the next table header.
  const table = config.split(/^\[/m).find((block) => block.startsWith(`orgs.${active}]`)) ?? "";
  const value = (key) => new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m").exec(table)?.[1];
  const organizationId = value("id");
  const keyPath = value("api_key_path");
  if (!organizationId || !keyPath) fail(`${path}: [orgs.${active}] needs id and api_key_path`);
  const key = readJson(keyPath);
  return { organizationId, apiBaseUrl: value("api_base_url") || TURNKEY_API, publicKey: key.public_key, privateKey: key.private_key };
}

/**
 * Turnkey's API-key stamp of `body`, the `X-Stamp` header: ECDSA P-256 over
 * SHA-256 of the body, DER, with the compressed public key that names the key.
 */
export function turnkeyStamp(body, { publicKey, privateKey }) {
  if (!HEX(32).test(privateKey ?? "") || !/^0[23][0-9a-f]{64}$/.test(publicKey ?? "")) {
    fail("the Turnkey API key must be a 32-byte private key and a compressed public key, in hex");
  }
  const secret = Buffer.from(privateKey, "hex");
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(secret);
  if (ecdh.getPublicKey("hex", "compressed") !== publicKey) fail("the Turnkey API key's private half does not match its public key");
  const point = ecdh.getPublicKey();
  const jwk = {
    kty: "EC",
    crv: "P-256",
    d: secret.toString("base64url"),
    x: point.subarray(1, 33).toString("base64url"),
    y: point.subarray(33).toString("base64url"),
  };
  const signature = sign("sha256", Buffer.from(body), createPrivateKey({ key: jwk, format: "jwk" })).toString("hex");
  return Buffer.from(JSON.stringify({ publicKey, scheme: "SIGNATURE_SCHEME_TK_API_P256", signature })).toString("base64url");
}

/** Fetches a replica's Boot Proof from Turnkey (`get_boot_proof`) with `credentials`. */
export function turnkeyBootProofs(credentials, transport = { fetch }) {
  return async (ephemeralKey) => {
    const body = JSON.stringify({ organizationId: credentials.organizationId, ephemeralKey });
    const response = await transport.fetch(new URL("/public/v1/query/get_boot_proof", credentials.apiBaseUrl), {
      method: "POST",
      headers: { "content-type": "application/json", "x-stamp": turnkeyStamp(body, credentials) },
      body,
    });
    if (!response.ok) fail(`Turnkey answered the Boot Proof lookup with ${response.status}: ${(await response.text()).slice(0, 300)}`);
    const { bootProof } = await response.json();
    if (!bootProof) fail("Turnkey has no Boot Proof for the replica that answered");
    return bootProof;
  };
}

/**
 * Verifies the replica that serves `info` as a client will, before anything
 * is signed: it answers a challenge sealed to `info`'s Quorum key, and its Boot
 * Proof chains to the pinned AWS Nitro root, carries release.json's
 * `qosIdentityPcrs` and attests `info`'s manifest digest, under the trust root
 * the release names. `bootProof` defaults to Turnkey with the `tvc` login.
 */
export async function verifyRelease(cfg, info, { bootProof, transport, nowMs } = {}) {
  if (!existsSync(CLIENT_TESTING)) {
    fail(`${relative(ROOT, CLIENT_TESTING)} is missing: the policy phase verifies the replica with it, so build tvc-wallet first (npx pnpm build:ts)`);
  }
  const { verifyLiveReplica } = await import(pathToFileURL(CLIENT_TESTING).href);
  try {
    await verifyLiveReplica({
      endpoint: new URL(cfg.endpoint),
      info,
      qosIdentityPcrs: cfg.qosIdentityPcrs,
      turnkeyTrustRootId: cfg.turnkeyTrustRootId,
      bootProof: bootProof ?? turnkeyBootProofs(tvcCredentials()),
      ...(transport ? { transport } : {}),
      ...(nowMs === undefined ? {} : { nowMs }),
    });
  } catch (error) {
    if (error instanceof ReleaseError) throw error;
    fail(`the replica at ${cfg.endpoint} does not verify, so nothing was signed: ${error.message}`);
  }
  console.log(`verified a replica at ${cfg.endpoint}: manifest ${info.manifest_digest} under the pinned PCRs`);
}

/**
 * The release file for `releaseId` as the enclave at `cfg.endpoint` serves it
 * (`info`): verified first, then signed. `verify` and `sign` are
 * `verifyRelease` and `signReleasePolicy`.
 */
export async function verifiedReleaseFile(releaseId, cfg, info, now, { verify = verifyRelease, sign = signReleasePolicy } = {}) {
  const unsigned = releasePolicy(releaseId, cfg, info, now);
  await verify(cfg, info);
  const signed = sign(unsigned, `${releaseId}-${new Date(now).toISOString().slice(0, 7)}`);
  return {
    releasePolicy: signed.releasePolicy,
    releaseAuthorities: signed.releaseAuthorities,
    qosIdentityPcrs: cfg.qosIdentityPcrs,
  };
}

async function policy(releaseId, cfg) {
  const info = await awaitRelease(releaseId, cfg);
  writeJson(pinPath(cfg), await verifiedReleaseFile(releaseId, cfg, info, Date.now()));
}

const USAGE =
  "usage: node scripts/release.mjs <build|deploy|policy|all> <release-id> --network <devnet|mainnet> " +
  `[--app <${Object.keys(APPS).join("|")}>] [--image <reference>] [--unattended] [--prune-deployments] ` +
  "[--operator-seeds <dir> --quorum-key-metadata <file>]";
const PHASES = ["build", "deploy", "policy"];

async function main() {
  let args;
  try {
    args = parseArgs({
      allowPositionals: true,
      options: {
        network: { type: "string" },
        app: { type: "string", default: "privacy-wallet" },
        image: { type: "string" },
        "operator-seeds": { type: "string" },
        "quorum-key-metadata": { type: "string" },
        unattended: { type: "boolean", default: false },
        "prune-deployments": { type: "boolean", default: false },
      },
    });
  } catch (error) {
    fail(`${error.message}\n${USAGE}`);
  }
  const { positionals, values } = args;
  const [phase, releaseId] = positionals;
  if (![...PHASES, "all"].includes(phase) || !releaseId || positionals.length > 2) fail(USAGE);
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(releaseId)) fail("release id: lowercase letters, digits and dashes");
  const { network } = values;
  if (!NETWORKS.includes(network)) fail(`--network must be devnet or mainnet\n${USAGE}`);
  // Each operator reviews the QOS manifest of a mainnet deployment before approving it.
  if (values.unattended && network === "mainnet") fail("--unattended is refused on mainnet: every approval is reviewed");
  if (!Object.hasOwn(APPS, values.app)) fail(`--app must be one of ${Object.keys(APPS).join(", ")}\n${USAGE}`);
  const seeds = values["operator-seeds"];
  const metadata = values["quorum-key-metadata"];
  if (Boolean(seeds) !== Boolean(metadata)) fail("--operator-seeds and --quorum-key-metadata go together");
  const cfg = config(network, values.app);
  for (const step of phase === "all" ? PHASES : [phase]) {
    console.log(`\n== ${step} ${releaseId} (${network})`);
    if (step === "build") build(releaseId, cfg, values.image);
    if (step === "deploy") {
      await deploy(releaseId, cfg, { unattended: values.unattended, prune: values["prune-deployments"], seeds, metadata });
    }
    if (step === "policy") await policy(releaseId, cfg);
  }
  console.log(
    `\n${releaseId}: done. Commit ${relative(ROOT, join(deployDir(cfg), network))} and ${relative(ROOT, pinPath(cfg))}.`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch (error) {
    if (!(error instanceof ReleaseError)) throw error;
    console.error(`error: ${error.message}`);
    process.exit(1);
  }
}
