import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { getAddressDecoder } from "@solana/kit";
import type { GlobalSetupContext } from "vitest/node";
import { PARENT_ORGANIZATION_ID, PROJECT_ID, testkit } from "./fixtures.js";
import { startMockDevApi } from "./mock-dev-api.js";
import { startMockTurnkey } from "./mock-turnkey.js";

declare module "vitest" {
  export interface ProvidedContext {
    stack: {
      /** The gateway's base URL; its routes are under `/v1/private-wallet`. */
      gatewayUrl: string;
      /** The `Authorization` value gatekeeper sends. */
      originAuth: string;
      /** A Helius API key of `PROJECT_ID`, for a direct caller. */
      apiKey: string;
      /** The Ed25519 seed of the wallet the testkit enclave holds, hex. */
      walletSeedHex: string;
    };
  }
}

const GATEWAY_DIR = resolve(import.meta.dirname, "..");
const REPO_DIR = resolve(GATEWAY_DIR, "../..");

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const p256Public = (secretHex: string, compressed: boolean) =>
  hex(p256.getPublicKey(Buffer.from(secretHex, "hex"), compressed));

function cargoBuild(...args: string[]) {
  execFileSync("cargo", ["build", "--quiet", ...args], { stdio: "inherit" });
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((done) => server.close(() => done()));
  return port;
}

function start(logs: string, name: string, command: string, args: string[], env: NodeJS.ProcessEnv = {}) {
  const log = openSync(join(logs, `${name}.log`), "w");
  return spawn(command, args, {
    cwd: GATEWAY_DIR,
    env: { ...process.env, ...env },
    stdio: ["ignore", log, log],
  });
}

async function waitForHealth(url: string, name: string, process: ChildProcess, logs: string) {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    if (process.exitCode !== null) break;
    const healthy = await fetch(`${url}/health`).then((response) => response.ok, () => false);
    if (healthy) return;
    await new Promise((done) => setTimeout(done, 500));
  }
  const log = readFileSync(join(logs, `${name}.log`), "utf8").split("\n").slice(-40).join("\n");
  throw new Error(`${name} did not come up at ${url}:\n${log}`);
}

export default async function setup({ provide }: GlobalSetupContext) {
  cargoBuild(
    "--manifest-path", join(REPO_DIR, "Cargo.toml"), "-p", "zolana-tvc-privacy-wallet",
    "--features", "local-dev", "--bin", "zolana-tvc-privacy-wallet-local",
  );
  cargoBuild(
    "--manifest-path", join(REPO_DIR, "Cargo.toml"), "-p", "zolana-tvc-protocol",
    "--example", "sign-release-policy",
  );
  cargoBuild("--manifest-path", join(GATEWAY_DIR, "Cargo.toml"), "--bin", "tvc-gateway");

  const logs = mkdtempSync(join(tmpdir(), "tvc-gateway-e2e-"));
  console.log(`tvc-gateway e2e logs: ${logs}`);

  const walletSeed = ed25519.utils.randomPrivateKey();
  const walletPublic = ed25519.getPublicKey(walletSeed);
  const walletKeypair = join(logs, "wallet.json");
  writeFileSync(walletKeypair, JSON.stringify([...walletSeed, ...walletPublic]));

  const turnkey = await startMockTurnkey(PROJECT_ID, getAddressDecoder().decode(walletPublic));
  const apiKey = randomUUID();
  const devApi = await startMockDevApi(apiKey, PROJECT_ID);
  const enclavePort = await freePort();
  const enclave = start(logs, "enclave", join(REPO_DIR, "target/debug/zolana-tvc-privacy-wallet-local"), [
    "--port", String(enclavePort), "--wallet-keypair", walletKeypair,
  ]);

  const policyDir = join(logs, "policy");
  execFileSync(join(REPO_DIR, "target/debug/examples/sign-release-policy"), ["--local-testkit", policyDir]);
  const gatewayPort = await freePort();
  const originAuth = `Bearer local-e2e-${hex(randomBytes(16))}`;
  const turnkeyKey = hex(randomBytes(32));
  const gateway = start(logs, "gateway", join(GATEWAY_DIR, "target/debug/tvc-gateway"), ["configs/config.yaml"], {
    TVC_GATEWAY_LISTEN: `127.0.0.1:${gatewayPort}`,
    TVC_GATEWAY_ORIGIN_AUTH_HEADER: originAuth,
    TVC_GATEWAY_DEV_API__BASE_URL: devApi.url,
    TVC_GATEWAY_ENCLAVE__BASE_URL: `http://127.0.0.1:${enclavePort}`,
    TVC_GATEWAY_TURNKEY__API_BASE_URL: turnkey.url,
    TVC_GATEWAY_TURNKEY__WAAS_PARENT_ORGANIZATION_ID: PARENT_ORGANIZATION_ID,
    TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PRIVATE_KEY: turnkeyKey,
    TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PUBLIC_KEY: p256Public(turnkeyKey, true),
    TVC_GATEWAY_TURNKEY__WAAS_API_KEY__PRIVATE_KEY: turnkeyKey,
    TVC_GATEWAY_TURNKEY__WAAS_API_KEY__PUBLIC_KEY: p256Public(turnkeyKey, true),
    TVC_GATEWAY_PROVISIONING__PRIVATE_KEY: testkit.provisioningPrivateKeyHex,
    TVC_GATEWAY_PROVISIONING__EXPECTED_PUBLIC_KEY: p256Public(testkit.provisioningPrivateKeyHex, false),
    TVC_GATEWAY_PROVISIONING__RELEASE_POLICY_PATH: join(policyDir, "release-policy.json"),
    TVC_GATEWAY_PROVISIONING__RELEASE_AUTHORITIES_PATH: join(policyDir, "release-authorities.json"),
    TVC_GATEWAY_WALLET_GRANT__PRIVATE_KEY: testkit.grantPrivateKeyHex,
    TVC_GATEWAY_WALLET_GRANT__EXPECTED_PUBLIC_KEY: p256Public(testkit.grantPrivateKeyHex, false),
    TVC_GATEWAY_ENROLLMENT__DOMAINS: JSON.stringify([`127.0.0.1:${gatewayPort}`]),
  });

  const teardown = async () => {
    enclave.kill();
    gateway.kill();
    await turnkey.close();
    await devApi.close();
  };
  try {
    await waitForHealth(`http://127.0.0.1:${enclavePort}`, "enclave", enclave, logs);
    await waitForHealth(`http://127.0.0.1:${gatewayPort}`, "gateway", gateway, logs);
  } catch (error) {
    await teardown();
    throw error;
  }
  provide("stack", {
    gatewayUrl: `http://127.0.0.1:${gatewayPort}`,
    originAuth,
    apiKey,
    walletSeedHex: hex(walletSeed),
  });
  return teardown;
}
