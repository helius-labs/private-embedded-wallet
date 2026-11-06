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
  createTvcClient,
  createTvcRequestSigner,
  type Network,
  type StoredWallet,
  type TvcClient,
  type TvcKeys,
  type TvcOpenOptions,
} from "@heliuslabs/spr-embedded-wallet";
import {
  clientKeyIdFor,
  encodeLowerHex,
  walletEnrollmentMessage,
  type WalletDescriptor,
} from "@heliuslabs/spr-embedded-wallet/protocol";
import { createLocalTvcClient, localProverConfig } from "@heliuslabs/spr-embedded-wallet/testing";
import { bootstrapWithApproval } from "./bootstrap-approval.js";

export type Client = Awaited<ReturnType<typeof createSprClient>>;

export interface ExampleSetup {
  readonly zolana: Client;
  /** The wallet's keys, held by the enclave: the SDK's `WalletKeys`. */
  readonly keys: TvcKeys;
  /** The wallet owner signs transactions and pays fees. */
  readonly signer: TransactionPartialSigner;
}

/** The enclave's client, the owner's transaction signer, and how the owner approves a bootstrap. */
interface WalletClient {
  readonly tvc: TvcClient;
  readonly signer: TransactionPartialSigner;
  readonly approve?: TvcOpenOptions["approve"];
}

export interface ConfirmedTransaction {
  readonly signature: Signature;
  /** Slot the transaction landed in; drives the indexer freshness gates. */
  readonly slot: bigint;
}

// Each network's Helius host. SPR_NETWORK picks one; it must be the network the
// enclave serves. Its gatekeeper serves the RPC, the indexer and the TEE prover
// at /v1/spr, and that network's tvc-gateway at /v1/private-wallet, which
// enrolls a device for the host it is called at.
const NETWORKS = {
  devnet: { host: "https://devnet.helius-rpc.com" },
  mainnet: { host: "https://mainnet.helius-rpc.com" },
} as const satisfies Record<Network, unknown>;
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

function networkFromEnv(): Network {
  const network = process.env["SPR_NETWORK"]?.trim() || "devnet";
  if (network !== "devnet" && network !== "mainnet") throw new Error("SPR_NETWORK must be devnet or mainnet");
  return network;
}

/** `path` on the network's Helius host, with `API_KEY`. */
export function heliusUrl(network: Network, path: string): string {
  const url = new URL(path, NETWORKS[network].host);
  url.searchParams.set("api-key", env("API_KEY"));
  return url.toString();
}

function clientConfigFromEnv(network: Network): SprClientConfig {
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

/** The stored descriptor, checked to enroll this client key on `network`. */
async function walletDescriptor(
  path: string,
  clientPublicKey: string,
  network: Network,
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
  if (descriptor.network !== network) {
    throw new Error(`${path} is a ${String(descriptor.network)} descriptor, and SPR_NETWORK is ${network}`);
  }
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

/** Requests signed with the enrolled client key. */
function requestSigner(key: { privateKey: webcrypto.CryptoKey; publicKey: Uint8Array }) {
  return createTvcRequestSigner({
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
function gatewayEndpoint(network: Network): URL {
  return new URL(process.env["TVC_GATEWAY_URL"]?.trim() || heliusUrl(network, "/v1/private-wallet"));
}

/**
 * The stored descriptor for this client key, or one the gateway issues: the
 * wallet owner signs a Sign-In With Solana message for the gateway's host and
 * network through Turnkey, and `POST /enroll` answers the descriptor.
 */
async function gatewayDescriptor(
  owner: TurnkeyApi,
  organizationId: string,
  network: Network,
  endpoint: URL,
  clientPublicKey: string,
  path: string,
): Promise<WalletDescriptor> {
  try {
    return await walletDescriptor(path, clientPublicKey, network);
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
    payload: walletEnrollmentMessage({ domain: endpoint.host, network, ...enrollment }),
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
  return walletDescriptor(path, clientPublicKey, network);
}

/**
 * The network's enclave through the hosted tvc-gateway, verified against the
 * release the package pins for the network. Any Helius API key reaches it;
 * the wallet's Turnkey sub-organization must be named after the key's project.
 */
async function gatewayClientFromEnv(network: Network): Promise<WalletClient> {
  const key = await clientKey(env("TVC_CLIENT_KEY_PATH"));
  const enrollIn = env("TURNKEY_ORGANIZATION_ID");
  const endpoint = gatewayEndpoint(network);
  const descriptor = await gatewayDescriptor(
    await turnkeyClient(enrollIn),
    enrollIn,
    network,
    endpoint,
    encodeLowerHex(key.publicKey),
    env("TVC_DESCRIPTOR_PATH"),
  );
  // The enclave seals proofs to /v1/spr beside the gateway unless TVC_PROVER_URL names another prover.
  const prover = process.env["TVC_PROVER_URL"]?.trim();
  const tvc = createTvcClient({
    network,
    endpoint,
    descriptor,
    signer: requestSigner(key),
    ...(prover ? { prover: new URL(prover) } : {}),
  });
  const organizationId = descriptor.turnkey_organization_id;
  const owner = await turnkeyClient(organizationId);
  const { servicePublicKey } = tvc;
  const expected = { organizationId, walletAddress: descriptor.address, servicePublicKey };
  return {
    tvc,
    signer: turnkeySigner(owner, descriptor),
    // The grant names the enclave's current service key, so it is set before
    // each bootstrap, including the one after a Quorum key rotation.
    async approve(bootstrap, signal) {
      await grantEnclaveBootstrap(owner, organizationId, servicePublicKey, descriptor.address);
      await bootstrapWithApproval(owner, expected, bootstrap, signal);
    },
  };
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

/** Use local process keys and a Solana keypair for the loopback-only testkit built for `network`. */
async function localTestkit(network: Network, endpoint: string): Promise<WalletClient> {
  const secret = JSON.parse(
    await readFile(env("TVC_SOLANA_KEYPAIR_PATH"), "utf8"),
  ) as unknown;
  if (!Array.isArray(secret) || secret.length !== 64) {
    throw new Error("TVC_SOLANA_KEYPAIR_PATH is not a Solana keypair file");
  }
  const signer = await createKeyPairSignerFromBytes(Uint8Array.from(secret));
  // TVC_PROVER_URL names a TEE prover of the network, for a testkit started
  // with --live-prover, under the network's policy; otherwise the testkit's
  // stand-in prover.
  const liveProver = process.env["TVC_PROVER_URL"]?.trim();
  const tvc = createLocalTvcClient({
    network,
    backend: { kind: "enclave", endpoint: new URL(endpoint) },
    solanaAddress: signer.address,
    prover: liveProver
      ? { url: liveProver }
      : localProverConfig(process.env["TVC_LOCAL_PROVER_URL"]?.trim() || LOCAL_PROVER_URL),
  });
  return { tvc, signer };
}

/** The SDK client, the wallet's keys from the enclave, and the owner's signer. */
export async function setup(): Promise<ExampleSetup> {
  await initializePoseidon();
  const network = networkFromEnv();
  const zolana = await createSprClient(clientConfigFromEnv(network));
  const testkit = process.env["TVC_LOCAL_TESTKIT_ENDPOINT"]?.trim();
  const { tvc, signer, approve } = testkit
    ? await localTestkit(network, testkit)
    : await gatewayClientFromEnv(network);
  const keys = await openWallet(tvc, env("TVC_WALLET_PATH"), approve ? { approve } : {});
  return Object.freeze({ zolana, keys, signer });
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

/** The stored wallet, or a wallet the enclave bootstraps once and the file then keeps. */
async function openWallet(tvc: TvcClient, path: string, options: TvcOpenOptions): Promise<TvcKeys> {
  const stored = await loadWallet(path);
  const keys = await tvc.open(stored, options);
  if (!stored) await writeFile(path, JSON.stringify(keys.stored, null, 2), { mode: 0o600 });
  return keys;
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
