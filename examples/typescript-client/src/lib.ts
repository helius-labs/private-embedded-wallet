import "dotenv/config";

import { webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

import {
  address,
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  createKeyPairSignerFromBytes,
  getPublicKeyFromAddress,
  getSignatureFromTransaction,
  getTransactionDecoder,
  getTransactionEncoder,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  verifySignature,
  type Address,
  type Signature,
  type SignatureDictionary,
  type Transaction,
  type TransactionPartialSigner,
} from "@solana/kit";
import {
  createSprClient,
  initializePoseidon,
  type SprClientConfig,
} from "@heliuslabs/spr";
import { SignedTeePolicy } from "@heliuslabs/spr/client";
import type { AssetBalance } from "@heliuslabs/spr/transaction";
import { DEFAULT_SOLANA_ACCOUNTS, Turnkey } from "@turnkey/sdk-server";
import {
  DEVNET_RELEASE,
  createTvcClient,
  createTvcOperationAuthorizer,
  identityOf,
  sealedSeedOf,
  type BootProofResolver,
  type SealedSeed,
  type QosIdentityPcrs,
  type ShieldedIdentity,
  type TvcClient,
  type TvcProverConfig,
  type TvcProverNetwork,
  TvcProverPolicy,
  type WalletDescriptor,
  type VerifiedConnection,
} from "@heliuslabs/spr-embedded-wallet";
import {
  clientKeyIdFor,
  encodeLowerHex,
  signWalletGrant,
  walletEnrollmentMessage,
  walletGrantSecret,
  type PinnedReleaseAuthorities,
  type SignedReleasePolicy,
} from "@heliuslabs/spr-embedded-wallet/protocol";
import { createLocalTvcClient, localProverConfig } from "@heliuslabs/spr-embedded-wallet/testing";
import { bootstrapWithApproval } from "./bootstrap-approval.js";

export type Client = Awaited<ReturnType<typeof createSprClient>>;

export interface ExampleSetup {
  readonly zolana: Client;
  readonly tvc: TvcClient;
  readonly connection: VerifiedConnection;
  /** The wallet owner signs transactions and pays fees. */
  readonly signer: TransactionPartialSigner;
  readonly walletPath: string;
  /** The attested prover the enclave seals proofs to; the client posts them. */
  readonly prover: TvcProverConfig;
}

export interface ConfirmedTransaction {
  readonly signature: Signature;
  /** Slot the transaction landed in; drives the indexer freshness gates. */
  readonly slot: bigint;
}

/** The two values `bootstrap` returns. Neither is a secret to the client. */
export interface StoredWallet {
  readonly identity: ShieldedIdentity;
  readonly sealedSeed: SealedSeed;
}

/** Independently pinned trust material for one TVC release. */
interface TrustMaterial {
  readonly releasePolicy: SignedReleasePolicy;
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  readonly qosIdentityPcrs: QosIdentityPcrs;
}

// Each network's Helius RPC. SPR_NETWORK picks one; it must be the network the
// enclave image was built for. Its gatekeeper serves the indexer and the TEE
// prover at /v1/spr and the hosted tvc-gateway at /v1/private-wallet.
const NETWORKS = {
  devnet: { rpc: "https://devnet.helius-rpc.com" },
  mainnet: { rpc: "https://mainnet.helius-rpc.com" },
} as const satisfies Record<TvcProverNetwork, unknown>;
const LOCAL_PROVER_URL = "http://127.0.0.1:44021";
const LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]"];
const TURNKEY_API_URL = "https://api.turnkey.com";
const P256 = { name: "ECDSA", namedCurve: "P-256" } as const;

function env(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`set ${name}`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

function networkFromEnv(): TvcProverNetwork {
  const network = process.env["SPR_NETWORK"]?.trim() || "devnet";
  if (network !== "devnet" && network !== "mainnet") throw new Error("SPR_NETWORK must be devnet or mainnet");
  return network;
}

/** `path` on the network's Helius host, with `API_KEY`. */
export function heliusUrl(network: TvcProverNetwork, path: string): string {
  const url = new URL(path, NETWORKS[network].rpc);
  url.searchParams.set("api-key", env("API_KEY"));
  return url.toString();
}

function clientConfigFromEnv(network: TvcProverNetwork): SprClientConfig {
  const solanaRpcUrl = process.env["ZOLANA_ENDPOINT"]?.trim() || heliusUrl(network, "/");
  const proverUrl = process.env["ZOLANA_PROVER_URL"]?.trim() || heliusUrl(network, "/v1/spr");
  return Object.freeze({
    solanaRpcUrl,
    indexerUrl: process.env["ZOLANA_INDEXER_URL"]?.trim() || heliusUrl(network, "/v1/spr"),
    proverUrl,
    // A local network's plaintext prover is the only one without a policy.
    ...(LOOPBACK_HOSTS.includes(new URL(proverUrl).hostname)
      ? {}
      : { proverTee: SignedTeePolicy.forNetwork(network) }),
    // The enclave completes resolved proof inputs; it has no indexed proving.
    proofDataSource: "client",
  });
}

/** Load operator-published trust pins independently of the service. */
async function trustMaterial(path: string): Promise<TrustMaterial> {
  const parsed = await readJson(path);
  if (
    !isRecord(parsed) ||
    !isRecord(parsed["releasePolicy"]) ||
    !isRecord(parsed["releaseAuthorities"]) ||
    !isRecord(parsed["qosIdentityPcrs"])
  ) {
    throw new Error(
      `${path} must hold releasePolicy, releaseAuthorities and qosIdentityPcrs`,
    );
  }
  return parsed as unknown as TrustMaterial;
}

/** Load or create the request-signing key enrolled in the wallet descriptor. */
export async function clientKey(
  path: string,
): Promise<{ privateKey: webcrypto.CryptoKey; publicKey: Uint8Array }> {
  let jwk: webcrypto.JsonWebKey;
  try {
    jwk = (await readJson(path)) as webcrypto.JsonWebKey;
  } catch (error) {
    if (!isRecord(error) || error["code"] !== "ENOENT") throw error;
    const pair = await webcrypto.subtle.generateKey(P256, true, ["sign"]);
    jwk = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
    await writeFile(path, JSON.stringify(jwk), { mode: 0o600, flag: "wx" });
  }
  const privateKey = await webcrypto.subtle.importKey("jwk", jwk, P256, false, [
    "sign",
  ]);
  const { kty, crv, x, y } = jwk;
  const publicJwk = await webcrypto.subtle.importKey(
    "jwk",
    { kty, crv, x, y },
    P256,
    true,
    ["verify"],
  );
  const publicKey = new Uint8Array(
    await webcrypto.subtle.exportKey("raw", publicJwk),
  );
  return { privateKey, publicKey };
}

/** Load the operator-signed descriptor and check that it enrolls this client key. */
/** The operator's wallet-grant key, `{"private_key": hex}`, checked to be the one the enclave pins. */
async function loadWalletGrantSecret(path: string): Promise<Uint8Array> {
  return walletGrantSecret(await readFile(path, "utf8"));
}

async function walletDescriptor(
  path: string,
  clientPublicKey: string,
): Promise<WalletDescriptor> {
  let parsed: unknown;
  try {
    parsed = await readJson(path);
  } catch {
    throw new Error(
      `no wallet descriptor at ${path}. ` +
        `Enroll client public key ${clientPublicKey} and save the descriptor there.`,
    );
  }
  if (!isRecord(parsed) || !Array.isArray(parsed["allowed_clients"])) {
    throw new Error(`${path} is not a wallet descriptor`);
  }
  const descriptor = parsed as unknown as WalletDescriptor;
  const allowed = descriptor.allowed_clients.some(
    (grant) => grant.client_public_key === clientPublicKey,
  );
  if (!allowed) {
    throw new Error(
      `${path} does not list client public key ${clientPublicKey}`,
    );
  }
  return descriptor;
}

/**
 * Read Boot Proof via the operator proxy, or directly with a TVC organization key.
 * Verification always uses the client's own pins.
 */
async function bootProofResolver(): Promise<BootProofResolver> {
  const url = process.env["TVC_BOOT_PROOF_URL"]?.trim();
  if (url) {
    return async ({ bootProofLookupKey }) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ephemeralKey: bootProofLookupKey }),
      });
      if (!response.ok) throw new Error(`boot proof: HTTP ${response.status}`);
      return response.json();
    };
  }
  const organizationId = process.env["TVC_ORGANIZATION_ID"]?.trim();
  if (!organizationId) throw new Error("set TVC_BOOT_PROOF_URL or TVC_ORGANIZATION_ID");
  const turnkey = await turnkeyClient(organizationId);
  return async ({ bootProofLookupKey }) =>
    (await turnkey.getBootProof({ organizationId, ephemeralKey: bootProofLookupKey }))
      .bootProof;
}

/** Operations signed with the enrolled client key. */
function requestAuthorizer(key: { privateKey: webcrypto.CryptoKey; publicKey: Uint8Array }) {
  return createTvcOperationAuthorizer({
    clientKeyId: clientKeyIdFor(key.publicKey),
    sign: async (message) =>
      new Uint8Array(
        await webcrypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          key.privateKey,
          message,
        ),
      ),
  });
}

/** The hosted tvc-gateway: `TVC_GATEWAY_URL`, else the network's `/v1/private-wallet`. */
function gatewayEndpoint(network: TvcProverNetwork): URL {
  return new URL(process.env["TVC_GATEWAY_URL"]?.trim() || heliusUrl(network, "/v1/private-wallet"));
}

/**
 * The stored descriptor for this client key, or one the gateway issues: the
 * wallet owner signs a Sign-In With Solana message for the gateway's host
 * through Turnkey, and `POST /enroll` answers the descriptor.
 */
async function gatewayDescriptor(
  owner: TurnkeyApi,
  organizationId: string,
  endpoint: URL,
  clientPublicKey: string,
  path: string,
): Promise<WalletDescriptor> {
  try {
    return await walletDescriptor(path, clientPublicKey);
  } catch (error) {
    if (!(error instanceof Error) || !error.message.startsWith("no wallet descriptor")) throw error;
  }
  const account = await walletAccount(owner, organizationId);
  const enrollment = {
    organizationId,
    turnkeyWalletId: account.walletId,
    solanaAddress: account.address,
    clientPublicKey,
    issuedAtMs: Date.now(),
  };
  const signed = await owner.signRawPayload({
    signWith: account.address,
    payload: walletEnrollmentMessage({ domain: endpoint.host, ...enrollment }),
    encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
    hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
  });
  const url = new URL(endpoint);
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/enroll`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...enrollment,
      ownerSignature: signed.r.padStart(64, "0") + signed.s.padStart(64, "0"),
    }),
  });
  const answer = (await response.json()) as unknown;
  if (!response.ok || !isRecord(answer) || !isRecord(answer["descriptor"])) {
    throw new Error(`enroll: HTTP ${response.status} ${JSON.stringify(answer)}`);
  }
  await writeFile(path, JSON.stringify(answer["descriptor"], null, 2));
  console.log(`enrolled client key with the gateway; descriptor saved at ${path}`);
  return walletDescriptor(path, clientPublicKey);
}

/**
 * The enclave through the hosted tvc-gateway. Any Helius API key reaches it;
 * the wallet's Turnkey sub-organization must be named after the key's project.
 */
async function gatewayClientFromEnv(network: TvcProverNetwork): Promise<{
  tvc: TvcClient;
  descriptor: WalletDescriptor;
  servicePublicKey: string;
}> {
  const trustPath = process.env["TVC_TRUST_PATH"]?.trim();
  const trust = trustPath ? await trustMaterial(trustPath) : DEVNET_RELEASE;
  const key = await clientKey(env("TVC_CLIENT_KEY_PATH"));
  const organizationId = env("TURNKEY_ORGANIZATION_ID");
  const endpoint = gatewayEndpoint(network);
  const descriptor = await gatewayDescriptor(
    await turnkeyClient(organizationId),
    organizationId,
    endpoint,
    encodeLowerHex(key.publicKey),
    env("TVC_DESCRIPTOR_PATH"),
  );
  const tvc = createTvcClient({
    backend: { kind: "gateway", endpoint },
    releasePolicy: trust.releasePolicy,
    releaseAuthorities: trust.releaseAuthorities,
    qosIdentityPcrs: trust.qosIdentityPcrs,
    operations: { walletDescriptor: descriptor, authorizer: requestAuthorizer(key) },
  });
  return { tvc, descriptor, servicePublicKey: enclaveServicePublicKey(trust.releasePolicy.policy.quorumPublicKey) };
}

async function tvcClientFromEnv(): Promise<{
  tvc: TvcClient;
  descriptor: WalletDescriptor;
  servicePublicKey: string;
}> {
  const trust = await trustMaterial(env("TVC_TRUST_PATH"));
  const key = await clientKey(env("TVC_CLIENT_KEY_PATH"));
  const clientPublicKey = encodeLowerHex(key.publicKey);
  const descriptor = await walletDescriptor(
    env("TVC_DESCRIPTOR_PATH"),
    clientPublicKey,
  );
  const authorizer = requestAuthorizer(key);
  const grantSecret = await loadWalletGrantSecret(env("TVC_WALLET_GRANT_KEY_PATH"));
  const walletGrant = () =>
    Promise.resolve(signWalletGrant({
      descriptor,
      clientKeyId: clientKeyIdFor(key.publicKey),
      projectId: "self-hosted",
      issuedAtMs: BigInt(Date.now()),
      lifetimeMs: 900_000n,
    }, grantSecret));
  const tvc = createTvcClient({
    backend: {
      kind: "enclave",
      endpoint: new URL(env("TVC_ENDPOINT")),
      resolveBootProof: await bootProofResolver(),
      walletGrant,
    },
    releasePolicy: trust.releasePolicy,
    releaseAuthorities: trust.releaseAuthorities,
    qosIdentityPcrs: trust.qosIdentityPcrs,
    operations: { walletDescriptor: descriptor, authorizer },
  });
  return { tvc, descriptor, servicePublicKey: enclaveServicePublicKey(trust.releasePolicy.policy.quorumPublicKey) };
}

function sameBytes(left: ArrayLike<number>, right: ArrayLike<number>): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/** Read owner credentials from environment variables or a Turnkey CLI key file. */
async function turnkeyApiKey(): Promise<{ publicKey: string; privateKey: string }> {
  const path = process.env["TURNKEY_API_KEY_PATH"]?.trim();
  if (!path) {
    return {
      publicKey: env("TURNKEY_API_PUBLIC_KEY"),
      privateKey: env("TURNKEY_API_PRIVATE_KEY"),
    };
  }
  const stored = await readJson(path);
  if (
    !isRecord(stored) ||
    typeof stored["public_key"] !== "string" ||
    typeof stored["private_key"] !== "string"
  ) {
    throw new Error(`${path} is not a Turnkey API key file`);
  }
  return { publicKey: stored["public_key"], privateKey: stored["private_key"] };
}

async function turnkeyClient(organizationId: string) {
  const { publicKey, privateKey } = await turnkeyApiKey();
  return new Turnkey({
    apiBaseUrl: TURNKEY_API_URL,
    apiPublicKey: publicKey,
    apiPrivateKey: privateKey,
    defaultOrganizationId: organizationId,
  }).apiClient();
}

type TurnkeyApi = Awaited<ReturnType<typeof turnkeyClient>>;
export type BootstrapApprovalApi = Pick<TurnkeyApi, "getActivity" | "getActivities" | "approveActivity">;

/** What the operator needs to sign this client's descriptor. */
export interface Enrollment {
  readonly organizationId: string;
  readonly walletId: string;
  readonly address: string;
  readonly clientPublicKey: string;
  readonly trustPath: string;
}

/** Turnkey uses the compressed signing point (the second of two quorum P-256 points). */
function enclaveServicePublicKey(quorumPublicKey: string): string {
  if (!/^04[0-9a-f]{128}04[0-9a-f]{128}$/.test(quorumPublicKey)) {
    throw new Error("the pinned quorum public key is not two P-256 points");
  }
  const signing = quorumPublicKey.slice(130);
  const x = signing.slice(2, 66);
  const yIsEven = Number.parseInt(signing.slice(-2), 16) % 2 === 0;
  return `${yIsEven ? "02" : "03"}${x}`;
}

/**
 * Require both the enclave and the owner to approve bootstrap. The owner checks
 * the exact derivation message because Turnkey policies cannot inspect raw payloads.
 */
export async function grantEnclaveBootstrap(
  turnkey: Pick<TurnkeyApi,
    "getUsers" | "createUsers" | "getPolicies" | "createPolicy" | "updatePolicy" | "getWhoami" | "getOrganizationConfigs">,
  organizationId: string,
  servicePublicKey: string,
  walletAddress: string,
): Promise<void> {
  const owner = await turnkey.getWhoami({ organizationId });
  if (owner.organizationId !== organizationId || !/^[a-zA-Z0-9-]+$/.test(owner.userId)) {
    throw new Error("Invalid bootstrap approver identity");
  }
  const { users } = await turnkey.getUsers({ organizationId });
  let userId = users.find((user) =>
    user.apiKeys.some(
      (apiKey) =>
        apiKey.credential.type === "CREDENTIAL_TYPE_API_KEY_P256" &&
        apiKey.credential.publicKey.replace(/^0x/, "").toLowerCase() ===
          servicePublicKey,
    ),
  )?.userId;
  if (userId === undefined) {
    const created = await turnkey.createUsers({
      organizationId,
      users: [
        {
          userName: "zolana-tvc-wallet-authority",
          apiKeys: [
            {
              apiKeyName: "zolana-tvc-wallet-quorum-key",
              publicKey: servicePublicKey,
              curveType: "API_KEY_CURVE_P256",
            },
          ],
          authenticators: [],
          oauthProviders: [],
          userTags: [],
        },
      ],
    });
    userId = created.userIds[0];
    if (userId === undefined) throw new Error("Turnkey created no user");
    console.log(`created enclave service user ${userId}`);
  }

  const { configs } = await turnkey.getOrganizationConfigs({ organizationId });
  if (!configs.quorum || userId === owner.userId || configs.quorum.userIds.includes(userId)) {
    throw new Error("The enclave must be a non-root user distinct from the bootstrap approver");
  }
  const policyName = `zolana-tvc-bootstrap-${walletAddress.slice(0, 12)}`;
  const condition = [
    "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2'",
    `wallet_account.address == '${walletAddress}'`,
    "activity.params.encoding == 'PAYLOAD_ENCODING_HEXADECIMAL'",
    "activity.params.hash_function == 'HASH_FUNCTION_NOT_APPLICABLE'",
  ].join(" && ");
  const consensus = `approvers.any(user, user.id == '${userId}') && approvers.any(user, user.id == '${owner.userId}')`;
  const notes = "TVC bootstrap requires the owner client to approve the exact derivation message.";
  const { policies } = await turnkey.getPolicies({ organizationId });
  const existing = policies.filter((policy) => policy.policyName === policyName);
  if (existing.length === 0) {
    const { policyId } = await turnkey.createPolicy({
      organizationId,
      policyName,
      effect: "EFFECT_ALLOW",
      condition,
      consensus,
      notes,
    });
    console.log(`created bootstrap policy ${policyId}`);
    return;
  }
  for (const policy of existing) {
    if (policy.effect === "EFFECT_ALLOW" && policy.condition === condition && policy.consensus === consensus) continue;
    await turnkey.updatePolicy({
      organizationId,
      policyId: policy.policyId,
      policyName,
      policyEffect: "EFFECT_ALLOW",
      policyCondition: condition,
      policyConsensus: consensus,
      policyNotes: notes,
    });
    console.log(`updated bootstrap policy ${policy.policyId}`);
  }
}

/** The Solana wallet account behind `TURNKEY_WALLET_ADDRESS`, or a new wallet when none is named. */
async function walletAccount(
  turnkey: TurnkeyApi,
  organizationId: string,
): Promise<{ walletId: string; address: string }> {
  const named = process.env["TURNKEY_WALLET_ADDRESS"]?.trim();
  if (named) {
    const { accounts } = await turnkey.getWalletAccounts({ organizationId });
    const account = accounts.find((entry) => entry.address === named);
    if (account === undefined) {
      throw new Error(`organization ${organizationId} has no wallet account ${named}`);
    }
    return { walletId: account.walletId, address: named };
  }
  const created = await turnkey.createWallet({
    organizationId,
    walletName: `zolana-tvc-example-${Date.now()}`,
    accounts: DEFAULT_SOLANA_ACCOUNTS,
  });
  const [address] = created.addresses;
  if (address === undefined) throw new Error("Turnkey created a wallet without an address");
  console.log(`created wallet ${created.walletId} with Solana address ${address}`);
  return { walletId: created.walletId, address };
}

/** Enroll the client and enclave keys; return the inputs for an operator-signed descriptor. */
export async function enroll(): Promise<Enrollment> {
  const trustPath = env("TVC_TRUST_PATH");
  const trust = await trustMaterial(trustPath);
  const key = await clientKey(env("TVC_CLIENT_KEY_PATH"));
  const organizationId = env("TURNKEY_ORGANIZATION_ID");
  const turnkey = await turnkeyClient(organizationId);
  const account = await walletAccount(turnkey, organizationId);
  await grantEnclaveBootstrap(
    turnkey,
    organizationId,
    enclaveServicePublicKey(trust.releasePolicy.policy.quorumPublicKey),
    account.address,
  );
  return Object.freeze({
    organizationId,
    walletId: account.walletId,
    address: account.address,
    clientPublicKey: encodeLowerHex(key.publicKey),
    trustPath,
  });
}

/** Adapt Turnkey to a Solana signer, verifying the returned message and wallet signature. */
function turnkeySigner(turnkey: TurnkeyApi, descriptor: WalletDescriptor): TransactionPartialSigner {
  const signer: Address = address(descriptor.address);
  const publicKey = getPublicKeyFromAddress(signer);
  const encoder = getTransactionEncoder();
  const decoder = getTransactionDecoder();
  return {
    address: signer,
    async signTransactions(
      transactions: readonly Transaction[],
    ): Promise<readonly SignatureDictionary[]> {
      const signatures: SignatureDictionary[] = [];
      for (const transaction of transactions) {
        if (!(signer in transaction.signatures)) {
          throw new Error("SignerNotRequired");
        }
        const { signedTransaction } = await turnkey.signTransaction({
          signWith: descriptor.address,
          unsignedTransaction: Buffer.from(
            encoder.encode(transaction),
          ).toString("hex"),
          type: "TRANSACTION_TYPE_SOLANA",
        });
        const signed = decoder.decode(Buffer.from(signedTransaction, "hex"));
        if (!sameBytes(signed.messageBytes, transaction.messageBytes)) {
          throw new Error("SignedTransactionMismatch");
        }
        const signature = signed.signatures[signer];
        if (!signature) throw new Error("MissingTransactionSignature");
        if (
          !(await verifySignature(
            await publicKey,
            signature,
            transaction.messageBytes,
          ))
        ) {
          throw new Error("InvalidTransactionSignature");
        }
        signatures.push({ [signer]: signature });
      }
      return signatures;
    },
  };
}

/** Use local process keys and a Solana keypair for the loopback-only testkit. */
async function localTestkit(endpoint: string): Promise<{
  tvc: TvcClient;
  signer: TransactionPartialSigner;
}> {
  const secret = JSON.parse(
    await readFile(env("TVC_SOLANA_KEYPAIR_PATH"), "utf8"),
  ) as unknown;
  if (!Array.isArray(secret) || secret.length !== 64) {
    throw new Error("TVC_SOLANA_KEYPAIR_PATH is not a Solana keypair file");
  }
  const signer = await createKeyPairSignerFromBytes(Uint8Array.from(secret));
  const tvc = createLocalTvcClient({
    backend: { kind: "enclave", endpoint: new URL(endpoint) },
    solanaAddress: signer.address,
  });
  return { tvc, signer };
}

export async function setup(): Promise<ExampleSetup> {
  await initializePoseidon();
  const network = networkFromEnv();
  const zolana = await createSprClient(clientConfigFromEnv(network));
  const walletPath = env("TVC_WALLET_PATH");
  const testkit = process.env["TVC_LOCAL_TESTKIT_ENDPOINT"]?.trim();
  if (testkit) {
    const local = await localTestkit(testkit);
    const connection = await local.tvc.connectAndVerify();
    // TVC_PROVER_URL names a TEE prover of the network, for a testkit
    // started with --live-prover; otherwise the testkit's stand-in prover.
    const liveProver = process.env["TVC_PROVER_URL"]?.trim();
    const prover = liveProver
      ? { url: liveProver, policy: TvcProverPolicy.forNetwork(network) }
      : localProverConfig(process.env["TVC_LOCAL_PROVER_URL"]?.trim() || LOCAL_PROVER_URL);
    return Object.freeze({ zolana, walletPath, ...local, connection, prover });
  }
  // TVC_ENDPOINT names the enclave itself, for an operator holding the trust
  // material and grant key; otherwise the hosted gateway.
  const { tvc: enclave, descriptor, servicePublicKey } = process.env["TVC_ENDPOINT"]?.trim()
    ? await tvcClientFromEnv()
    : await gatewayClientFromEnv(network);
  const connection = await enclave.connectAndVerify();
  const organizationId = descriptor.turnkey_organization_id;
  const owner = await turnkeyClient(organizationId);
  // Remove legacy service-only grants even when reusing a stored seed.
  await grantEnclaveBootstrap(owner, organizationId, servicePublicKey, descriptor.address);
  const expected = { organizationId, walletAddress: descriptor.address, servicePublicKey };
  const tvc: TvcClient = {
    ...enclave,
    bootstrap: (verified, options) => bootstrapWithApproval(
      owner, expected,
      (signal) => enclave.bootstrap(verified, { ...options, signal }),
      options?.signal,
    ),
  };
  return Object.freeze({
    zolana, tvc, connection,
    signer: turnkeySigner(owner, descriptor),
    walletPath,
    prover: {
      url: process.env["TVC_PROVER_URL"]?.trim() || heliusUrl(network, "/v1/spr"),
      policy: TvcProverPolicy.forNetwork(network),
    },
  });
}

/** The stored identity and sealed seed, or `undefined` before the first bootstrap. */
async function loadWallet(
  path: string,
): Promise<StoredWallet | undefined> {
  let parsed: unknown;
  try {
    parsed = await readJson(path);
  } catch {
    return undefined;
  }
  if (
    !isRecord(parsed) ||
    !isRecord(parsed["identity"]) ||
    !isRecord(parsed["sealedSeed"]) ||
    typeof parsed["sealedSeed"]["sealedSeed"] !== "string"
  ) {
    throw new Error(`${path} is not a stored wallet`);
  }
  return parsed as unknown as StoredWallet;
}

/** Bootstrap once, then reuse the stored public identity and sealed seed. */
export async function loadOrBootstrapWallet(
  tvc: TvcClient,
  connection: VerifiedConnection,
  path: string,
): Promise<StoredWallet> {
  const stored = await loadWallet(path);
  if (stored) return stored;

  const result = await tvc.bootstrap(connection, {});
  const wallet = { identity: identityOf(result), sealedSeed: sealedSeedOf(result) };
  await writeFile(path, JSON.stringify(wallet, null, 2), { mode: 0o600 });
  return wallet;
}

export { env as requiredEnv };

/** Lookup table entries become usable in the slot after they were written. */
export async function awaitSlotAfter(client: Client, slot: bigint): Promise<void> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const current = await client.solanaRpc.getSlot({ commitment: client.commitment }).send();
    if (BigInt(current) > slot) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`the chain did not pass slot ${slot}`);
}

/** The private balance an example step must have reached, or the step failed. */
export function expectBalance(
  step: string,
  balance: AssetBalance,
  amount: bigint,
  utxos?: number,
): void {
  if (balance.amount !== amount) {
    throw new Error(
      `${step}: expected amount ${amount}, got ${balance.amount}`,
    );
  }
  if (utxos !== undefined && balance.utxos.length !== utxos) {
    throw new Error(
      `${step}: expected ${utxos} utxo(s), got ${balance.utxos.length}`,
    );
  }
}

/** Sign and confirm an SDK transaction; return its slot for the next indexer sync. */
export function sendAndConfirmFactory(
  client: Client,
  signer: TransactionPartialSigner,
): (transaction: Transaction) => Promise<ConfirmedTransaction> {
  const sendTransaction = sendTransactionWithoutConfirmingFactory({
    rpc: client.solanaRpc,
  });

  return async function sendAndConfirm(
    transaction: Transaction,
  ): Promise<ConfirmedTransaction> {
    const signed = await signTransactionWithSigners([signer], transaction);
    assertIsFullySignedTransaction(signed);
    assertIsTransactionWithinSizeLimit(signed);
    await sendTransaction(signed, { commitment: client.commitment });
    const signature = getSignatureFromTransaction(signed);
    const slot = await client.confirmTransaction(signature);
    return { signature, slot };
  };
}
