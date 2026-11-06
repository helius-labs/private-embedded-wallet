#!/usr/bin/env node
// Signs a wallet descriptor: the operator's grant that lets one client key
// drive the enclave operations of one Turnkey wallet.
//
//   node scripts/provision-descriptor.mjs --organization-id <uuid> --wallet-id <id> \
//     --address <solana address> --client-public-key <65-byte hex> [--out <path>] \
//     [--provisioning-key <path>] [--trust <path>]
//
// The security domain, environment and operation list come from the published
// trust material (packages/tvc-wallet/src/devnet-release.json), so the
// descriptor names exactly the release the client pins. The provisioning key is
// read from TVC_PROVISIONING_KEY_JSON or the --provisioning-key file, both the
// Turnkey API key format ({"private_key": "<hex>"}), checked against the public
// key compiled into the enclave, used for one signature and wiped.
//
// A descriptor is not a secret: it names public keys and identifiers. Send it
// to the client, which stores it at its TVC_DESCRIPTOR_PATH. It needs
// `pnpm build:ts` for the tvc-wallet entries it imports.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";

const ROOT = resolve(import.meta.dirname, "..");
const DEFAULT_TRUST = "packages/tvc-wallet/src/devnet-release.json";

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function readText(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    fail(`${path}: ${error.message}`);
  }
}

async function entry(name) {
  try {
    return await import(resolve(ROOT, `packages/tvc-wallet/dist/${name}.js`));
  } catch {
    fail("packages/tvc-wallet is not built: run `pnpm install && pnpm build:ts` first");
  }
}

const { values } = parseArgs({
  options: {
    "organization-id": { type: "string" },
    "wallet-id": { type: "string" },
    address: { type: "string" },
    "client-public-key": { type: "string" },
    out: { type: "string" },
    "provisioning-key": { type: "string" },
    trust: { type: "string", default: DEFAULT_TRUST },
  },
});
for (const name of ["organization-id", "wallet-id", "address", "client-public-key"]) {
  if (!values[name]) fail(`--${name} is required`);
}

const keyJson = process.env.TVC_PROVISIONING_KEY_JSON?.trim();
if (!keyJson && !values["provisioning-key"]) {
  fail("set TVC_PROVISIONING_KEY_JSON or pass --provisioning-key <path>");
}
const trust = JSON.parse(readText(resolve(ROOT, values.trust)));
if (!trust.releasePolicy?.policy) fail(`${values.trust} does not hold a release policy`);

const { TvcError } = await entry("protocol");
const { provisioningSecret, signWalletDescriptor } = await entry("operator");
let descriptor;
try {
  const secret = provisioningSecret(keyJson ?? readText(values["provisioning-key"]));
  try {
    descriptor = signWalletDescriptor(
      {
        releasePolicy: trust.releasePolicy.policy,
        turnkeyOrganizationId: values["organization-id"],
        turnkeyWalletId: values["wallet-id"],
        address: values.address,
        clientPublicKey: values["client-public-key"],
      },
      secret,
    );
  } finally {
    secret.fill(0);
  }
} catch (error) {
  if (error instanceof TvcError) fail(error.message);
  throw error;
}

const json = `${JSON.stringify(descriptor, null, 2)}\n`;
if (values.out) {
  writeFileSync(values.out, json);
  const client = descriptor.allowed_clients[0].client_public_key;
  console.log(`wrote ${values.out} for client ${client.slice(0, 18)}… on wallet ${descriptor.address}`);
} else {
  process.stdout.write(json);
}
