#!/usr/bin/env node
// Creates a P-256 service key (the provisioning key or the wallet-grant key)
// straight into a new AWS Secrets Manager secret as `{"private_key": hex}` and
// prints only its uncompressed public key, the value the enclave pins:
//
//   node scripts/create-service-key.mjs <secret-name> [--region <region>] [--profile <profile>]
//
// The private key exists only in this process and in the secret. The secret
// must not exist yet; an existing key is never overwritten.

import { execFileSync } from "node:child_process";
import { createECDH } from "node:crypto";

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

const [name, ...rest] = process.argv.slice(2);
if (!name || name.startsWith("--")) {
  fail("usage: node scripts/create-service-key.mjs <secret-name> [--region <region>] [--profile <profile>]");
}
const flag = (option) => {
  const index = rest.indexOf(option);
  return index === -1 ? [] : [option, rest[index + 1] ?? fail(`${option} needs a value`)];
};

const ecdh = createECDH("prime256v1");
ecdh.generateKeys();
const secret = ecdh.getPrivateKey();
const publicKey = ecdh.getPublicKey("hex");
try {
  execFileSync(
    "aws",
    [
      "secretsmanager", "create-secret",
      ...flag("--region"), ...flag("--profile"),
      "--name", name,
      "--description", "SPR TVC service key (P-256); its public key is compiled into the enclave",
      "--secret-string", "file:///dev/stdin",
      "--query", "ARN", "--output", "text",
    ],
    { input: JSON.stringify({ private_key: secret.toString("hex") }), stdio: ["pipe", "ignore", "inherit"] },
  );
} catch {
  fail(`could not create ${name}; nothing was written`);
} finally {
  secret.fill(0);
}
console.log(`created ${name}`);
console.log(`public key: ${publicKey}`);
