#!/usr/bin/env node
// Releases the privacy wallet in four phases, each resumable on its own:
//
//   build   reads the /tvc_app digest from the --image the
//           publish-privacy-wallet-image workflow pushed and records the
//           deployment descriptor
//   deploy  creates the TVC deployment, approves it for every operator,
//           provisions it, makes it live, and waits for /v1/info to answer
//           with the new release
//   policy  reads /v1/info, assembles the release policy, signs it with a
//           one-time authority key, and writes the trust material
//   pins    writes the signed policy and its authorities into tvc-gateway's
//           configs, and the trust material into wallet-kit's package
//
//   node scripts/release.mjs <build|deploy|policy|pins|all> <release-id> [--image <reference>] [--wallet-kit <dir>] [--unattended] [--prune-deployments] [--api-key <org>]
//
// Operator approvals are interactive: the CLI shows the QOS manifest and asks
// each operator to confirm it, which is the point of the approval. Pass
// --unattended to approve without that review (tvc's --dangerous-skip-interactive).
//
// Turnkey keeps at most three deployable deployments per app. With
// --prune-deployments the deploy phase deletes the oldest ones that are neither
// live nor the one being released until the new one fits, through the Turnkey
// API: the organization is in release.json, the operator API key is the one
// `tvc login` stored (or TVC_API_KEY_PUBLIC / TVC_API_KEY_PRIVATE).
//
// The constants of the deployment live in apps/privacy-wallet/deploy/release.json.
// Docker, the Turnkey `tvc` CLI (logged in for the operators) and cargo are
// used where they are needed; nothing here holds a key longer than one call.

import { execFileSync, spawnSync } from "node:child_process";
import { createECDH, createPrivateKey, sign as signWithKey } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = resolve(import.meta.dirname, "..");
const DEPLOY_DIR = join(ROOT, "apps/privacy-wallet/deploy");
const OPERATIONS = ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"];
const HEX64 = /^[0-9a-f]{64}$/;
const HEX = (bytes) => new RegExp(`^[0-9a-f]{${2 * bytes}}$`);
const INFO_TIMEOUT_MS = 20 * 60_000;
const TURNKEY_API = "https://api.turnkey.com";
/** Turnkey's cap on deployable deployments per TVC app. */
const DEPLOYABLE_LIMIT = 3;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${path}`);
}

/** Runs a command with inherited output; the release stops on the first failure. */
function run(command, args, options = {}) {
  console.log(`$ ${[command, ...args].join(" ")}`);
  const result = spawnSync(command, args, { stdio: "inherit", cwd: ROOT, ...options });
  if (result.status !== 0) fail(`${command} ${args[0] ?? ""} failed`);
}

/** Runs a command and returns its stdout; the command line is still shown. */
function capture(command, args, options = {}) {
  console.log(`$ ${[command, ...args].join(" ")}`);
  try {
    return execFileSync(command, args, { encoding: "utf8", cwd: ROOT, stdio: ["ignore", "pipe", "inherit"], ...options });
  } catch (error) {
    // A CLI that answers in JSON reports its failure on stdout; show it.
    if (error.stdout) console.error(String(error.stdout).trim());
    fail(`${command} ${args.filter((arg) => !arg.startsWith("--")).slice(0, 3).join(" ")} failed (exit ${error.status ?? "?"})`);
  }
}

function config() {
  const value = readJson(join(DEPLOY_DIR, "release.json"));
  for (const key of ["appId", "turnkeyOrganizationId", "endpoint", "imageRepository", "qosVersion", "securityDomainId", "quorumKeyId", "quorumKeyEpoch"]) {
    if (typeof value[key] !== "string" || value[key] === "") fail(`release.json: ${key} is required`);
  }
  if (!Array.isArray(value.operatorIds) || value.operatorIds.length === 0) fail("release.json: operatorIds is required");
  for (const index of ["0", "1", "2", "3"]) {
    if (!HEX(48).test(value.qosIdentityPcrs?.[index] ?? "")) fail(`release.json: qosIdentityPcrs.${index} must be 48-byte hex`);
  }
  return value;
}

const descriptorPath = (releaseId) => join(DEPLOY_DIR, `privacy-wallet-${releaseId}.deployment.json`);
const deploymentPath = (releaseId) => join(DEPLOY_DIR, `privacy-wallet-${releaseId}.deploy.json`);
const trustPath = (releaseId) => join(DEPLOY_DIR, `privacy-wallet-${releaseId}.trust.json`);
const CURRENT_TRUST = join(DEPLOY_DIR, "privacy-wallet.trust.json");

function build(releaseId, cfg, image) {
  if (!image) fail("build needs --image, the reference publish-privacy-wallet-image reports");
  if (!image.startsWith(`${cfg.imageRepository}:`) || !/^[^@]+@sha256:[0-9a-f]{64}$/.test(image)) {
    fail(`--image must be ${cfg.imageRepository}:<tag>@sha256:<digest>`);
  }
  const pivotDigest = capture("docker", ["run", "--rm", "--platform", "linux/amd64", "--entrypoint", "sha256sum", image, "/tvc_app"]).split(/\s+/)[0];
  if (!HEX64.test(pivotDigest)) fail(`could not read the /tvc_app digest: ${pivotDigest}`);
  writeJson(descriptorPath(releaseId), {
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

/** The `tvc` CLI, non-interactive with JSON answers. */
function tvc(args) {
  const output = capture("tvc", ["--non-interactive", "--message-format", "json", ...args]);
  try {
    return JSON.parse(output);
  } catch {
    return output;
  }
}

function deploymentId(answer) {
  const id = answer?.deployId ?? answer?.deploymentId ?? answer?.deployment?.id ?? answer?.id;
  if (typeof id !== "string") fail(`could not find the deployment id in the tvc answer:\n${JSON.stringify(answer, null, 2)}`);
  return id;
}

async function fetchInfo(endpoint) {
  const response = await fetch(new URL("v1/info", `${endpoint}/`));
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/** Waits until the live deployment is the one being released. */
async function awaitRelease(releaseId, cfg, expectedPivotDigest) {
  const deadline = Date.now() + INFO_TIMEOUT_MS;
  for (;;) {
    try {
      const info = await fetchInfo(cfg.endpoint);
      if (info.release_id === releaseId && info.executable_digest === expectedPivotDigest) return info;
      console.log(`live: ${info.release_id} (${info.executable_digest.slice(0, 16)}…), waiting for ${releaseId}`);
    } catch (error) {
      console.log(`/v1/info: ${error.message}, waiting`);
    }
    if (Date.now() > deadline) fail(`${cfg.endpoint} did not serve ${releaseId} within ${INFO_TIMEOUT_MS / 60_000} minutes`);
    await sleep(15_000);
  }
}

/**
 * The deployment record is also the phase's progress: a re-run continues
 * from the last step that succeeded instead of creating a second deployment.
 */
function deploymentRecord(releaseId) {
  try {
    return readJson(deploymentPath(releaseId));
  } catch {
    return null;
  }
}

/**
 * A stamped Turnkey API request with the operator's API key: the body is
 * signed with P-256 over SHA-256 and the DER signature travels in `X-Stamp`.
 */
/**
 * The operator API key: TVC_API_KEY_PUBLIC / TVC_API_KEY_PRIVATE when set, as
 * the tvc CLI itself reads them, otherwise what `tvc login` stored under
 * ~/.config/turnkey: orgs/<org>/api_key.json for the active org named in
 * tvc.config.toml (or the only org, or --api-key <org>).
 */
function operatorApiKey(orgName) {
  const fromEnv = [process.env.TVC_API_KEY_PUBLIC?.trim(), process.env.TVC_API_KEY_PRIVATE?.trim()];
  if (fromEnv[0] && fromEnv[1]) return { publicKey: fromEnv[0], privateKey: fromEnv[1] };
  const turnkeyDir = join(homedir(), ".config/turnkey");
  const orgsDir = join(turnkeyDir, "orgs");
  const orgs = existsSync(orgsDir) ? readdirSync(orgsDir).filter((entry) => existsSync(join(orgsDir, entry, "api_key.json"))) : [];
  const configPath = join(turnkeyDir, "tvc.config.toml");
  const active = existsSync(configPath)
    ? readFileSync(configPath, "utf8").match(/^\s*active[_-]?org\s*=\s*"([^"]+)"/m)?.[1]
    : undefined;
  const org = orgName ?? (orgs.length === 1 ? orgs[0] : active && orgs.includes(active) ? active : undefined);
  if (!org) {
    fail(
      orgs.length === 0
        ? `no operator API key: run \`tvc login\` (read from ${orgsDir}/<org>/api_key.json) or set TVC_API_KEY_PUBLIC and TVC_API_KEY_PRIVATE`
        : `several logins in ${orgsDir} (${orgs.join(", ")}): choose one with --api-key <org>`,
    );
  }
  if (!orgs.includes(org)) fail(`no login named ${org} in ${orgsDir}`);
  const stored = readJson(join(orgsDir, org, "api_key.json"));
  const pick = (...names) => names.map((name) => stored[name]).find((value) => typeof value === "string");
  const publicKey = pick("public_key", "publicKey", "public");
  const privateKey = pick("private_key", "privateKey", "private");
  if (!publicKey || !privateKey) {
    fail(`${join(orgsDir, org, "api_key.json")} has keys ${Object.keys(stored).join(", ")}; expected public_key and private_key`);
  }
  return { publicKey, privateKey };
}

async function turnkey(cfg, path, body) {
  const organizationId = cfg.turnkeyOrganizationId;
  const { publicKey, privateKey } = operatorApiKey(cfg.apiKeyName);
  const secret = Buffer.from(privateKey, "hex");
  if (secret.length !== 32) fail("the operator API private key must be 32-byte hex");
  if (!/^0[23][0-9a-f]{64}$/.test(publicKey)) fail("the operator API public key must be compressed P-256 hex");
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(secret);
  const point = ecdh.getPublicKey();
  const base64url = (bytes) => Buffer.from(bytes).toString("base64url");
  const key = createPrivateKey({
    format: "jwk",
    key: { kty: "EC", crv: "P-256", d: base64url(secret), x: base64url(point.subarray(1, 33)), y: base64url(point.subarray(33, 65)) },
  });
  secret.fill(0);
  const payload = JSON.stringify({ organizationId, ...body });
  const signature = signWithKey("sha256", Buffer.from(payload), { key, dsaEncoding: "der" }).toString("hex");
  const stamp = base64url(JSON.stringify({ publicKey, scheme: "SIGNATURE_SCHEME_TK_API_P256", signature }));
  // A query is safe to repeat; a submit is stamped once and sent once, since
  // a second delivery would be a second activity.
  const attempts = path.startsWith("/public/v1/query/") ? 3 : 1;
  for (let attempt = 1; ; attempt += 1) {
    let response;
    try {
      response = await fetch(`${TURNKEY_API}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", "X-Stamp": stamp },
        body: payload,
      });
    } catch (error) {
      const reason = error.cause?.message ?? error.message;
      if (attempt >= attempts) fail(`Turnkey ${path}: ${reason}`);
      console.log(`Turnkey ${path}: ${reason}, retrying`);
      await sleep(3_000 * attempt);
      continue;
    }
    const answer = await response.json();
    if (!response.ok) fail(`Turnkey ${path}: HTTP ${response.status} ${JSON.stringify(answer)}`);
    return answer;
  }
}

/** Deletes the oldest deployments that are neither live nor ours until ours fits under the cap. */
async function pruneDeployments(cfg, keepDeployId) {
  const { tvcApp } = await turnkey(cfg, "/public/v1/query/get_tvc_app", { tvcAppId: cfg.appId });
  const { tvcDeployments } = await turnkey(cfg, "/public/v1/query/list_tvc_app_deployments", { appId: cfg.appId });
  const keep = new Set([tvcApp.liveDeploymentId, keepDeployId].filter(Boolean));
  const others = tvcDeployments
    .filter((deployment) => !deployment.delete && !keep.has(deployment.id))
    .sort((a, b) => Number(a.createdAt.seconds) - Number(b.createdAt.seconds));
  // Ours is in the list already; it counts against the cap once approved.
  const remaining = tvcDeployments.filter((deployment) => !deployment.delete).length;
  for (let excess = remaining - DEPLOYABLE_LIMIT; excess > 0 && others.length > 0; excess -= 1) {
    const oldest = others.shift();
    const release = oldest.pivotContainer?.args?.at(oldest.pivotContainer.args.indexOf("--release-id") + 1) ?? "unknown release";
    console.log(`deleting deployment ${oldest.id} (${release}, created ${new Date(Number(oldest.createdAt.seconds) * 1000).toISOString()})`);
    await turnkey(cfg, "/public/v1/submit/delete_tvc_deployment", {
      type: "ACTIVITY_TYPE_DELETE_TVC_DEPLOYMENT",
      timestampMs: String(Date.now()),
      parameters: { deploymentId: oldest.id },
    });
  }
}

async function waitFor(label, ready) {
  const deadline = Date.now() + INFO_TIMEOUT_MS;
  while (!(await ready())) {
    if (Date.now() > deadline) fail(`timed out waiting for ${label}`);
    console.log(`waiting for ${label}`);
    await sleep(15_000);
  }
}

async function deploy(releaseId, cfg, unattended, prune) {
  const descriptor = readJson(descriptorPath(releaseId));
  let record = deploymentRecord(releaseId);
  if (!record) {
    const created = tvc(["deploy", "create", "--config-file", descriptorPath(releaseId)]);
    record = { deployId: deploymentId(created), created, approved: [], provisioned: [], live: false };
    writeJson(deploymentPath(releaseId), record);
  } else {
    console.log(`continuing deployment ${record.deployId}`);
    record = { approved: [], provisioned: [], live: false, ...record };
  }
  const save = () => writeJson(deploymentPath(releaseId), record);
  const { deployId } = record;
  if (prune) await pruneDeployments(cfg, deployId);
  // Each operator's approval is a signature over the QOS manifest; the CLI
  // must be logged in with a key that can act for the operator.
  for (const operatorId of cfg.operatorIds) {
    if (record.approved.includes(operatorId)) continue;
    const approve = ["deploy", "approve", "--deploy-id", deployId, "--operator-id", operatorId];
    if (unattended) tvc([...approve, "--dangerous-skip-interactive"]);
    else run("tvc", approve);
    record.approved.push(operatorId);
    save();
  }
  // Provisioning hands each share-set member its share of the Quorum key.
  if (!Array.isArray(record.provisioned)) record.provisioned = [];
  if (cfg.operatorIds.some((id) => !record.provisioned.includes(id))) {
    await waitFor("provisioning attestation", async () => {
      const details = await turnkey(cfg, "/public/v1/query/get_tvc_deployment_provisioning_details", { deploymentId: deployId });
      return typeof details.attestationDocument === "string" && details.attestationDocument.length > 0;
    });
  }
  for (const operatorId of cfg.operatorIds) {
    if (record.provisioned.includes(operatorId)) continue;
    tvc(["deploy", "provision", "--deploy-id", deployId, "--operator-id", operatorId]);
    record.provisioned.push(operatorId);
    save();
  }
  if (!record.live) {
    await waitFor("healthy deployment replicas", () =>
      tvc(["deploy", "get-status", "--deploy-id", deployId]).replicas?.ready > 0,
    );
    // An app's first deployment is live once healthy, and Turnkey refuses to set it live again.
    const { tvcApp } = await turnkey(cfg, "/public/v1/query/get_tvc_app", { tvcAppId: cfg.appId });
    if (tvcApp.liveDeploymentId !== deployId) tvc(["app", "set-live-deploy", "--deploy-id", deployId]);
    record.live = true;
    save();
  }
  await awaitRelease(releaseId, cfg, descriptor.expectedPivotDigest);
}

async function policy(releaseId, cfg) {
  const descriptor = readJson(descriptorPath(releaseId));
  const info = await awaitRelease(releaseId, cfg, descriptor.expectedPivotDigest);
  const same = (field, expected) => {
    if (info[field] !== expected) fail(`/v1/info ${field} is ${info[field]}, expected ${expected}`);
  };
  same("environment", "development");
  same("security_domain_id", cfg.securityDomainId);
  same("quorum_key_id", cfg.quorumKeyId);
  same("quorum_key_epoch", cfg.quorumKeyEpoch);
  if (!HEX64.test(info.manifest_digest)) fail("/v1/info manifest_digest is not 32-byte hex");
  if (!HEX(130).test(info.quorum_public_key)) fail("/v1/info quorum_public_key is not a QOS public key");
  if (JSON.stringify([...info.supported_operations].sort()) !== JSON.stringify([...OPERATIONS].sort())) {
    fail(`/v1/info supported_operations are ${info.supported_operations.join(", ")}`);
  }

  const now = Date.now();
  const unsigned = {
    version: 1,
    releaseId,
    environment: "development",
    tvcApplicationId: cfg.appId,
    securityDomainId: cfg.securityDomainId,
    acceptedManifestDigests: [info.manifest_digest],
    acceptedExecutableDigests: [descriptor.expectedPivotDigest],
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
  const stamp = new Date(now).toISOString().slice(0, 7);
  const authoritySetId = `${releaseId}-${stamp}`;

  // The authority key is generated inside the signer, used once, and gone
  // when it exits; only the signed policy and the public half come back.
  const scratch = mkdtempSync(join(tmpdir(), "zolana-tvc-release-"));
  let signed;
  try {
    const unsignedPath = join(scratch, "policy.json");
    writeFileSync(unsignedPath, JSON.stringify(unsigned));
    signed = JSON.parse(
      capture("cargo", ["run", "-q", "-p", "zolana-tvc-protocol", "--example", "sign-release-policy", "--", unsignedPath, authoritySetId]),
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  const trust = {
    releasePolicy: signed.releasePolicy,
    releaseAuthorities: signed.releaseAuthorities,
    qosIdentityPcrs: cfg.qosIdentityPcrs,
  };
  writeJson(trustPath(releaseId), trust);
  writeJson(CURRENT_TRUST, trust);
}

/** A TypeScript object literal: JSON with bare keys. */
function literal(value) {
  return JSON.stringify(value, null, 2).replace(/^(\s*)"([A-Za-z_$][\w$]*|\d+)":/gm, "$1$2:");
}

/** JSON in the layout of tvc-gateway's pinned files: objects expanded, arrays of scalars on one line. */
function gatewayJson(value, indent = "") {
  if (Array.isArray(value)) {
    if (value.every((item) => item === null || typeof item !== "object")) {
      return `[${value.map((item) => JSON.stringify(item)).join(", ")}]`;
    }
    const inner = `${indent}  `;
    return `[\n${value.map((item) => `${inner}${gatewayJson(item, inner)}`).join(",\n")}\n${indent}]`;
  }
  if (value !== null && typeof value === "object") {
    const inner = `${indent}  `;
    const entries = Object.entries(value).map(([key, item]) => `${inner}${JSON.stringify(key)}: ${gatewayJson(item, inner)}`);
    return entries.length === 0 ? "{}" : `{\n${entries.join(",\n")}\n${indent}}`;
  }
  return JSON.stringify(value);
}

function pins(releaseId, walletKit) {
  const trust = readJson(trustPath(releaseId));

  const gatewayConfigs = join(ROOT, "apps/tvc-gateway/configs");
  for (const [file, value] of [["release-policy.json", trust.releasePolicy], ["release-authorities.json", trust.releaseAuthorities]]) {
    writeFileSync(join(gatewayConfigs, file), `${gatewayJson(value)}\n`);
    console.log(`wrote ${join(gatewayConfigs, file)}`);
  }

  const releaseFile = join(walletKit, "packages/wallet-kit/src/private/internal/release.ts");
  let source = readFileSync(releaseFile, "utf8");
  const replaceConst = (name, type, value) => {
    const pattern = new RegExp(`export const ${name} = \\{[\\s\\S]*?\\n\\} as const satisfies ${type};`);
    if (!pattern.test(source)) fail(`${releaseFile}: no \`export const ${name}\` block`);
    source = source.replace(pattern, () => `export const ${name} = ${literal(value)} as const satisfies ${type};`);
  };
  replaceConst("PRIVATE_WALLET_RELEASE_POLICY", "SignedReleasePolicy", trust.releasePolicy);
  replaceConst("PRIVATE_WALLET_RELEASE_AUTHORITIES", "PinnedReleaseAuthorities", trust.releaseAuthorities);
  replaceConst("PRIVATE_WALLET_QOS_IDENTITY_PCRS", "QosIdentityPcrs", trust.qosIdentityPcrs);
  writeFileSync(releaseFile, source);
  // wallet-kit is formatted with prettier 3 defaults and pins no formatter of its own.
  run("npx", ["--yes", "prettier@3.9.9", "--write", releaseFile], { cwd: walletKit });
}

async function main() {
  const [phase, releaseId, ...rest] = process.argv.slice(2);
  if (!["build", "deploy", "policy", "pins", "all"].includes(phase ?? "") || !releaseId) {
    fail("usage: node scripts/release.mjs <build|deploy|policy|pins|all> <release-id> [--image <reference>] [--wallet-kit <dir>] [--unattended] [--prune-deployments] [--api-key <org>]");
  }
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(releaseId)) fail("release id: lowercase letters, digits and dashes");
  const walletKitFlag = rest.indexOf("--wallet-kit");
  const walletKit = resolve(ROOT, walletKitFlag === -1 ? "../wallet-kit" : rest[walletKitFlag + 1] ?? fail("--wallet-kit needs a path"));
  const unattended = rest.includes("--unattended");
  const prune = rest.includes("--prune-deployments");
  const imageFlag = rest.indexOf("--image");
  const image = imageFlag === -1 ? undefined : rest[imageFlag + 1] ?? fail("--image needs a reference");
  const cfg = config();
  const apiKeyFlag = rest.indexOf("--api-key");
  if (apiKeyFlag !== -1) cfg.apiKeyName = rest[apiKeyFlag + 1] ?? fail("--api-key needs an org name");
  const phases = phase === "all" ? ["build", "deploy", "policy", "pins"] : [phase];
  for (const step of phases) {
    console.log(`\n== ${step} ${releaseId}`);
    if (step === "build") build(releaseId, cfg, image);
    if (step === "deploy") await deploy(releaseId, cfg, unattended, prune);
    if (step === "policy") await policy(releaseId, cfg);
    if (step === "pins") pins(releaseId, walletKit);
  }
  console.log(`\n${releaseId}: done. Commit apps/privacy-wallet/deploy, apps/tvc-gateway/configs and the wallet-kit pins, then run the demo and \`examples/typescript-client\` against ${cfg.endpoint}.`);
}

await main();
