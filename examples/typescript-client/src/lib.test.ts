import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { clientKey, grantEnclaveBootstrap, heliusUrl } from "./lib.js";

test("client keys are created only for missing files and survive reload", async () => {
  const dir = await mkdtemp(join(tmpdir(), "tvc-client-key-"));
  try {
    const path = join(dir, "key.json");
    const created = await clientKey(path);
    const stored = await readFile(path, "utf8");
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual((await clientKey(path)).publicKey, created.publicKey);
    assert.equal(await readFile(path, "utf8"), stored);

    await writeFile(path, "{recoverable but broken JSON");
    await assert.rejects(clientKey(path), SyntaxError);
    assert.equal(await readFile(path, "utf8"), "{recoverable but broken JSON");

    await writeFile(path, '{"kty":"invalid"}');
    await assert.rejects(clientKey(path));
    assert.equal(await readFile(path, "utf8"), '{"kty":"invalid"}');

    await assert.rejects(clientKey(dir), { code: "EISDIR" });
    assert.equal((await stat(dir)).isDirectory(), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("enrollment reconciles every existing grant after quorum rotation", async () => {
  type Api = Parameters<typeof grantEnclaveBootstrap>[0];
  type Policy = Awaited<ReturnType<Api["getPolicies"]>>["policies"][number];
  const servicePublicKey = "02" + "11".repeat(32);
  const wallet = "4E2agEUkMiuP3ABYbYTYXuU7bYyqPb3uGsLqs7RDd1U5";
  const policies: Policy[] = [];
  let userExists = false;
  let creates = 0;
  let updates = 0;
  let ownerId = "owner-user";
  let rootIds = [ownerId];
  const api: Api = {
    getWhoami: async () => ({ organizationId: "org", userId: ownerId }) as Awaited<ReturnType<Api["getWhoami"]>>,
    getOrganizationConfigs: async () => ({ configs: { quorum: { threshold: 1, userIds: rootIds } } }) as Awaited<ReturnType<Api["getOrganizationConfigs"]>>,
    getUsers: async () => ({ users: userExists ? [{
      userId: "new-user",
      apiKeys: [{ credential: { type: "CREDENTIAL_TYPE_API_KEY_P256", publicKey: servicePublicKey } }],
    }] : [] }) as Awaited<ReturnType<Api["getUsers"]>>,
    createUsers: async () => {
      userExists = true;
      return { userIds: ["new-user"] } as Awaited<ReturnType<Api["createUsers"]>>;
    },
    getPolicies: async () => ({ policies }),
    createPolicy: async (input) => {
      creates++;
      policies.push({ ...input, policyId: "policy-1" } as Policy);
      return { policyId: "policy-1" } as Awaited<ReturnType<Api["createPolicy"]>>;
    },
    updatePolicy: async (input) => {
      updates++;
      const policy = policies.find((p) => p.policyId === input.policyId)!;
      Object.assign(policy, {
        condition: input.policyCondition, consensus: input.policyConsensus, effect: input.policyEffect,
      });
      return {} as Awaited<ReturnType<Api["updatePolicy"]>>;
    },
  };
  const grant = () => grantEnclaveBootstrap(api, "org", servicePublicKey, wallet);
  await grant();
  assert.equal(creates, 1);
  assert.match(policies[0]!.consensus!, /owner-user/);
  assert.match(policies[0]!.condition!, /activity.params.encoding == 'PAYLOAD_ENCODING_HEXADECIMAL'/);
  assert.match(policies[0]!.condition!, /activity.params.hash_function == 'HASH_FUNCTION_NOT_APPLICABLE'/);
  await grant();
  assert.equal(updates, 0);
  policies[0]!.consensus = "approvers.any(user, user.id == 'old-user')";
  policies[0]!.condition = "true";
  policies.push({ ...policies[0]!, policyId: "duplicate" });
  await grant();
  assert.equal(updates, 2);
  assert.equal(creates, 1);
  for (const policy of policies) {
    assert.equal(policy.consensus, "approvers.any(user, user.id == 'new-user') && approvers.any(user, user.id == 'owner-user')");
    assert.match(policy.condition!, /wallet_account.address/);
  }
  await grant();
  assert.equal(updates, 2);

  rootIds = ["new-user"];
  await assert.rejects(grant(), /non-root user distinct/);
  rootIds = ["owner-user"];
  ownerId = "new-user";
  await assert.rejects(grant(), /non-root user distinct/);
  ownerId = "owner-user";

  policies[0]!.consensus = "old-user";
  api.updatePolicy = async () => { throw new Error("update failed"); };
  await assert.rejects(grant(), /update failed/);
});

test("gatekeeper routes take the network's Helius host and the API key", () => {
  const saved = process.env["API_KEY"];
  process.env["API_KEY"] = "key&1";
  try {
    assert.equal(heliusUrl("devnet", "/v1/spr"), "https://devnet.helius-rpc.com/v1/spr?api-key=key%261");
    assert.equal(
      heliusUrl("mainnet", "/v1/private-wallet"),
      "https://mainnet.helius-rpc.com/v1/private-wallet?api-key=key%261",
    );
    assert.equal(heliusUrl("devnet", "/"), "https://devnet.helius-rpc.com/?api-key=key%261");
    delete process.env["API_KEY"];
    assert.throws(() => heliusUrl("devnet", "/v1/spr"), /set API_KEY/);
  } finally {
    if (saved === undefined) delete process.env["API_KEY"];
    else process.env["API_KEY"] = saved;
  }
});
