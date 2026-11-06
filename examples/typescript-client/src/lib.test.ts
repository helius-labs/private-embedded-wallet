import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { apiKeyTurnkey, grantEnclaveBootstrap, heliusUrl } from "./lib.js";

test("the owner's API key is the Turnkey session the client signs and enrolls with", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = privateKey.export({ format: "jwk" });
  const key = {
    privateKey: Buffer.from(jwk.d!, "base64url").toString("hex"),
    publicKey: Buffer.from(
      publicKey.export({ format: "der", type: "spki" }).subarray(-65),
    ).toString("hex"),
  };
  // Turnkey names API keys by their compressed public key.
  const point = Buffer.from(key.publicKey, "hex");
  key.publicKey = Buffer.from([2 + (point[64]! & 1), ...point.subarray(1, 33)]).toString("hex");
  const signed: unknown[] = [];
  type Api = Parameters<typeof apiKeyTurnkey>[0];
  const api: Api = {
    getWallets: async () => ({ wallets: [{ walletId: "w1" }] }) as Awaited<ReturnType<Api["getWallets"]>>,
    getWalletAccounts: async ({ walletId }) => ({
      accounts: [{ walletId, address: "owner", addressFormat: "ADDRESS_FORMAT_SOLANA" }],
    }) as Awaited<ReturnType<Api["getWalletAccounts"]>>,
    signRawPayload: async (input) => {
      signed.push(input);
      return { r: "01", s: "02", v: "00" } as Awaited<ReturnType<Api["signRawPayload"]>>;
    },
  };
  const turnkey = apiKeyTurnkey(api, "org", key);

  assert.deepEqual(await turnkey.getSession(), { publicKey: key.publicKey, organizationId: "org" });
  const message = "spr-tvc-client-auth-v1:" + "ab".repeat(32);
  const signature = Buffer.from(await turnkey.signWithApiKey({ message, publicKey: key.publicKey }), "hex");
  assert.equal(signature.length, 64);
  assert.equal(verify("sha256", Buffer.from(message), { key: publicKey, dsaEncoding: "ieee-p1363" }, signature), true);
  await assert.rejects(turnkey.signWithApiKey({ message, publicKey: "02" + "11".repeat(32) }), /no Turnkey API key/);

  const [wallet] = await turnkey.fetchWallets();
  assert.equal(wallet?.walletId, "w1");
  assert.equal(wallet?.accounts[0]?.address, "owner");
  await turnkey.signMessage({
    message: "enroll",
    walletAccount: wallet!.accounts[0]!,
    encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
    hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
  });
  assert.deepEqual(signed, [{
    organizationId: "org",
    signWith: "owner",
    payload: "enroll",
    encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
    hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
  }]);

  assert.throws(() => apiKeyTurnkey(api, "org", { ...key, publicKey: "02" + "11".repeat(32) }), /does not match/);
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
