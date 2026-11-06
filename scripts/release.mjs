#!/usr/bin/env node
// Releases the privacy wallet of one network in three phases, each resumable
// on its own:
//
//   build   reads the /tvc_app digest from the network's image that
//           publish-privacy-wallet-image pushed and writes the deployment
//           descriptor
//   deploy  creates the TVC deployment, approves and provisions it for every
//           operator, makes it live, and waits for /v1/info to serve it
//   policy  assembles the release policy from /v1/info, signs it with a
//           one-time authority key, and pins it in tvc-wallet's
//           src/releases/<network>.json, the file tvc-gateway reads too
//
//   node scripts/release.mjs <build|deploy|policy|all> <release-id>
//     --network <devnet|mainnet> [--image <reference>] [--unattended]
//     [--prune-deployments]
//
// Turnkey is driven through the `tvc` CLI and its active login. Approvals are
// interactive: the CLI shows the QOS manifest for each operator to confirm.
// --unattended approves without that review, on devnet only.
// --prune-deployments deletes the oldest deployments that are neither live nor
// this release's until it fits under Turnkey's cap. The constants are in
// apps/privacy-wallet/deploy/release.json, shared at the top and per network
// under `networks`; each network's deployment files are in
// apps/privacy-wallet/deploy/<network>/.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const ROOT = resolve(import.meta.dirname, "..");
const DEPLOY_DIR = join(ROOT, "apps/privacy-wallet/deploy");
const NETWORKS = ["devnet", "mainnet"];
/** `API_VERSION` in crates/protocol/src/constants.rs: the release policy and `/v1/info` version. */
const API_VERSION = 1;
/** The operations, in the order the enclave advertises them and clients compare them. */
const OPERATIONS = ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"];
const HEX = (bytes) => new RegExp(`^[0-9a-f]{${2 * bytes}}$`);
const WAIT_MS = 20 * 60_000;
/** Turnkey's cap on deployable deployments per TVC app. */
const DEPLOYABLE_LIMIT = 3;

/** The network's release pin in tvc-wallet, which tvc-gateway reads too. */
const pinPath = (network) => join(ROOT, "packages/tvc-wallet/src/releases", `${network}.json`);
const descriptorPath = (cfg, releaseId) => join(DEPLOY_DIR, cfg.network, `privacy-wallet-${releaseId}.deployment.json`);
const recordPath = (cfg, releaseId) => join(DEPLOY_DIR, cfg.network, `privacy-wallet-${releaseId}.deploy.json`);

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
function config(network) {
  const { networks, ...shared } = readJson(join(DEPLOY_DIR, "release.json"));
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
  return { ...shared, ...net, network };
}

function build(releaseId, cfg, image) {
  if (!image) fail("build needs --image, the reference publish-privacy-wallet-image reports");
  // The publish workflow tags each image with the network whose prover policy
  // and keys it was built with.
  const tag = `${cfg.imageRepository}:privacy-wallet-${cfg.network}-`;
  if (!image.startsWith(tag) || !/^[^@]+@sha256:[0-9a-f]{64}$/.test(image)) {
    fail(`--image must be ${tag}<commit>@sha256:<digest>, the ${cfg.network} image publish-privacy-wallet-image reports`);
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

/** The deployment record is the phase's progress: a re-run continues where the last one stopped. */
async function deploy(releaseId, cfg, { unattended, prune }) {
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

  for (const operatorId of cfg.operatorIds.filter((id) => !record.approved.includes(id))) {
    const approve = ["deploy", "approve", "--deploy-id", deployId, "--operator-id", operatorId];
    if (unattended) tvc(...approve, "--dangerous-skip-interactive");
    else run("tvc", approve);
    record.approved.push(operatorId);
    save();
  }

  // Provisioning hands each operator's share of the Quorum key to the
  // enclave, once its attestation is up and tvc has verified it.
  const unprovisioned = cfg.operatorIds.filter((id) => !record.provisioned.includes(id));
  if (unprovisioned.length > 0) {
    await waitFor("the provisioning attestation", () => tvcSucceeds("deploy", "provisioning-details", "--deploy-id", deployId));
  }
  for (const operatorId of unprovisioned) {
    tvc("deploy", "provision", "--deploy-id", deployId, "--operator-id", operatorId);
    record.provisioned.push(operatorId);
    save();
  }

  if (!record.live) {
    await waitFor("a ready replica", () => tvc("deploy", "get-status", "--deploy-id", deployId).replicas?.ready > 0);
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
  if (!Array.isArray(info.supported_operations) || info.supported_operations.join() !== OPERATIONS.join()) {
    fail(`/v1/info supported_operations are ${info.supported_operations}, expected ${OPERATIONS.join(", ")}`);
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
    allowedOperations: OPERATIONS,
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

async function policy(releaseId, cfg) {
  const info = await awaitRelease(releaseId, cfg);
  const now = Date.now();
  const unsigned = releasePolicy(releaseId, cfg, info, now);
  const signed = signReleasePolicy(unsigned, `${releaseId}-${new Date(now).toISOString().slice(0, 7)}`);
  writeJson(pinPath(cfg.network), {
    releasePolicy: signed.releasePolicy,
    releaseAuthorities: signed.releaseAuthorities,
    qosIdentityPcrs: cfg.qosIdentityPcrs,
  });
}

const USAGE =
  "usage: node scripts/release.mjs <build|deploy|policy|all> <release-id> --network <devnet|mainnet> " +
  "[--image <reference>] [--unattended] [--prune-deployments]";
const PHASES = ["build", "deploy", "policy"];

async function main() {
  let args;
  try {
    args = parseArgs({
      allowPositionals: true,
      options: {
        network: { type: "string" },
        image: { type: "string" },
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
  const cfg = config(network);
  for (const step of phase === "all" ? PHASES : [phase]) {
    console.log(`\n== ${step} ${releaseId} (${network})`);
    if (step === "build") build(releaseId, cfg, values.image);
    if (step === "deploy") await deploy(releaseId, cfg, { unattended: values.unattended, prune: values["prune-deployments"] });
    if (step === "policy") await policy(releaseId, cfg);
  }
  console.log(
    `\n${releaseId}: done. Commit ${relative(ROOT, join(DEPLOY_DIR, network))} and ${relative(ROOT, pinPath(network))}.`,
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
