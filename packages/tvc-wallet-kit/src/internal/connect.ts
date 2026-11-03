import { createPrivateZolanaClient } from "./zolana";
import { revocableWalletKeys } from "./revocable-keys";
import {
  clearPrivateWalletState,
  loadKnownIdentity,
  loadPrivateWalletState,
  saveKnownIdentity,
  savePrivateWalletState,
  type PrivateWalletState,
} from "./state";
import {
  PRIVATE_WALLET_QOS_IDENTITY_PCRS,
  PRIVATE_WALLET_RELEASE_AUTHORITIES,
  PRIVATE_WALLET_RELEASE_POLICY,
  PRIVATE_WALLET_SERVICE_PUBLIC_KEY,
} from "./release";
import {
  TVC_ENROLLMENT_DOMAIN,
  type HeliusTvcAuthority,
  type HeliusWalletSession,
  type HeliusWalletSessionWallet,
} from "helius-wallet-kit/core";
import type { WalletKeys } from "@heliuslabs/zolana";
import type { ZolanaClient } from "@heliuslabs/zolana/client";
import { address, type Address } from "@solana/kit";
import {
  createTvcClient,
  DEVNET_PROVER_POLICY,
  identityOf,
  sealedSeedOf,
  TvcKeys,
  type OperationsConfig,
  type ShieldedIdentity,
  type TvcClient,
  type TvcClientConfig,
  type TvcTransport,
  type VerifiedConnection,
} from "@zolana/tvc-wallet";
import {
  walletEnrollmentMessage,
  type OperationKind,
  type WalletDescriptor,
} from "@zolana/tvc-wallet/protocol";
import {
  loadOrCreatePersistentBrowserTvcAuthorizer,
  type PersistentBrowserTvcAuthorizer,
} from "@zolana/tvc-wallet/browser";

const CLIENT_KEY_DATABASE = "helius-wallet-kit-private-authorizer-v1";
const PRIVATE_API_PATH = "/api/tvc";

type BootstrapWithApproval = <T>(
  expectedWalletAddress: string,
  start: (signal: AbortSignal) => Promise<T>,
  signal: AbortSignal,
) => Promise<T>;

export type OpenPrivateWalletInput = {
  readonly origin: string;
  readonly solanaRpcUrl: string;
  readonly walletSession: HeliusWalletSession;
  readonly wallet: HeliusWalletSessionWallet;
  readonly signal: AbortSignal;
  readonly withBootstrapApproval: BootstrapWithApproval;
};

function hasCurrentOperationGrant(
  descriptor: WalletDescriptor,
  expected: readonly OperationKind[],
): boolean {
  return (
    descriptor.allowed_clients.length === 1 &&
    descriptor.allowed_clients.every(
      (grant) =>
        grant.allowed_operations.length === expected.length &&
        grant.allowed_operations.every(
          (operation, index) => operation === expected[index],
        ),
    )
  );
}

function sameIdentity(
  left: ShieldedIdentity,
  right: ShieldedIdentity,
): boolean {
  return (
    left.solanaAddress === right.solanaAddress &&
    left.shieldedOwnerHash === right.shieldedOwnerHash &&
    left.shieldedNullifierPublicKey === right.shieldedNullifierPublicKey &&
    left.shieldedViewingPublicKey === right.shieldedViewingPublicKey
  );
}

function sameAuthority(
  left: HeliusTvcAuthority,
  right: HeliusTvcAuthority,
): boolean {
  return (
    left.serviceUserId === right.serviceUserId &&
    left.apiKeyId === right.apiKeyId
  );
}

function stateMatches(
  state: PrivateWalletState,
  wallet: HeliusWalletSessionWallet,
  authorizer: PersistentBrowserTvcAuthorizer,
): boolean {
  const descriptor = state.walletDescriptor;
  return (
    state.turnkeyServicePublicKey === PRIVATE_WALLET_SERVICE_PUBLIC_KEY &&
    state.clientKeyId === authorizer.clientKeyId &&
    descriptor.address === wallet.address &&
    descriptor.turnkey_organization_id === wallet.organizationId &&
    descriptor.turnkey_wallet_id === wallet.walletId &&
    descriptor.security_domain_id ===
      PRIVATE_WALLET_RELEASE_POLICY.policy.securityDomainId &&
    descriptor.allowed_clients[0]?.client_public_key ===
      authorizer.clientPublicKey &&
    hasCurrentOperationGrant(
      descriptor,
      PRIVATE_WALLET_RELEASE_POLICY.policy.allowedOperations,
    )
  );
}

function scopedTransport(signal: AbortSignal): TvcTransport {
  return {
    fetch(input, init) {
      signal.throwIfAborted();
      return fetch(input, {
        ...init,
        signal: init?.signal
          ? AbortSignal.any([signal, init.signal])
          : signal,
      });
    },
  };
}

/** tvc-gateway through the host's route handler, which adds what gatekeeper would. */
function clientConfig(
  origin: string,
  signal: AbortSignal,
  operations?: OperationsConfig,
): TvcClientConfig {
  return {
    backend: { kind: "gateway", endpoint: new URL(PRIVATE_API_PATH, origin) },
    releasePolicy: PRIVATE_WALLET_RELEASE_POLICY,
    releaseAuthorities: PRIVATE_WALLET_RELEASE_AUTHORITIES,
    qosIdentityPcrs: PRIVATE_WALLET_QOS_IDENTITY_PCRS,
    transport: scopedTransport(signal),
    ...(operations ? { operations } : {}),
  };
}

async function verifiedClient(
  origin: string,
  signal: AbortSignal,
  state?: PrivateWalletState,
  authorizer?: PersistentBrowserTvcAuthorizer,
): Promise<{ client: TvcClient; connection: VerifiedConnection }> {
  const operations =
    state && authorizer
      ? { walletDescriptor: state.walletDescriptor, authorizer: authorizer.authorizer }
      : undefined;
  const client = createTvcClient(clientConfig(origin, signal, operations));
  const connection = await client.connectAndVerify();
  signal.throwIfAborted();
  return { client, connection };
}

/** Enrolls this browser's client key with the wallet owner's signature, in one request. */
async function enrollDevice(
  origin: string,
  walletSession: HeliusWalletSession,
  wallet: HeliusWalletSessionWallet,
  authorizer: PersistentBrowserTvcAuthorizer,
  authority: HeliusTvcAuthority,
  signal: AbortSignal,
): Promise<PrivateWalletState> {
  const enrollment = {
    organizationId: wallet.organizationId,
    turnkeyWalletId: wallet.walletId,
    solanaAddress: wallet.address,
    clientPublicKey: authorizer.clientPublicKey,
    issuedAtMs: Date.now(),
  };
  const ownerSignature = await walletSession.signTvcEnrollment(
    walletEnrollmentMessage({
      domain: TVC_ENROLLMENT_DOMAIN,
      ...enrollment,
    }),
  );
  signal.throwIfAborted();
  const response = await fetch(`${origin}${PRIVATE_API_PATH}/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...enrollment, ownerSignature }),
    signal,
  });
  if (!response.ok) throw new Error("DescriptorProvisioningDenied");
  const { descriptor } = (await response.json()) as { descriptor?: WalletDescriptor };
  if (!descriptor || typeof descriptor !== "object") {
    throw new Error("DescriptorProvisioningDenied");
  }
  const state: PrivateWalletState = {
    version: 7,
    clientKeyId: authorizer.clientKeyId,
    walletDescriptor: descriptor,
    identity: null,
    sealedSeed: null,
    registered: false,
    turnkeyServicePublicKey: PRIVATE_WALLET_SERVICE_PUBLIC_KEY,
    tvcAuthority: authority,
  };
  if (!stateMatches(state, wallet, authorizer)) {
    throw new Error("WalletDescriptorBindingMismatch");
  }
  await savePrivateWalletState(state);
  signal.throwIfAborted();
  return state;
}

async function loadCurrentState(
  wallet: HeliusWalletSessionWallet,
  authorizer: PersistentBrowserTvcAuthorizer,
): Promise<PrivateWalletState | null> {
  let state: PrivateWalletState | null;
  try {
    state = await loadPrivateWalletState(wallet.address);
  } catch {
    await clearPrivateWalletState(wallet.address);
    state = null;
  }
  if (state && !stateMatches(state, wallet, authorizer)) {
    await clearPrivateWalletState(wallet.address);
    return null;
  }
  return state;
}

async function ensureIdentity(
  state: PrivateWalletState,
  client: TvcClient,
  connection: VerifiedConnection,
  withBootstrapApproval: BootstrapWithApproval,
  signal: AbortSignal,
): Promise<PrivateWalletState> {
  const ownerAddress = state.walletDescriptor.address;
  const knownIdentity = await loadKnownIdentity(ownerAddress);
  signal.throwIfAborted();
  if (state.identity && state.sealedSeed) {
    if (knownIdentity && !sameIdentity(state.identity, knownIdentity)) {
      throw new Error("ShieldedIdentityChanged");
    }
    if (!knownIdentity) await saveKnownIdentity(state.identity);
    return state;
  }
  const bootstrap = await withBootstrapApproval(
    ownerAddress,
    (bootstrapSignal) =>
      client.bootstrap(connection, {
        ...(knownIdentity ? { expectedIdentity: knownIdentity } : {}),
        signal: bootstrapSignal,
      }),
    signal,
  );
  if (bootstrap.solana_address !== ownerAddress) {
    throw new Error("WalletBindingMismatch");
  }
  const identity = identityOf(bootstrap);
  const nextState: PrivateWalletState = {
    ...state,
    identity,
    sealedSeed: sealedSeedOf(bootstrap),
  };
  await savePrivateWalletState(nextState);
  await saveKnownIdentity(identity);
  signal.throwIfAborted();
  return nextState;
}

/** The low-level Zolana capabilities bound to the authenticated public account. */
export type OpenedPrivateWallet = Readonly<{
  /** The public account whose signing material deterministically owns `keys`. */
  ownerAddress: Address;
  /** Shielded key operations backed by the independently verified TVC. */
  keys: WalletKeys;
  /** Zolana client configured for the supported private-wallet deployment. */
  zolana: ZolanaClient;
}>;

/** Opens only the TVC-backed keys and an ordinary Zolana client. */
export async function openPrivateWallet(
  input: OpenPrivateWalletInput,
): Promise<OpenedPrivateWallet> {
  const { origin, walletSession, wallet, signal } = input;
  signal.throwIfAborted();
  const authorizer = await loadOrCreatePersistentBrowserTvcAuthorizer({
    databaseName: CLIENT_KEY_DATABASE,
  });
  signal.throwIfAborted();
  let state = await loadCurrentState(wallet, authorizer);

  let client: TvcClient;
  let connection: VerifiedConnection;
  if (state) {
    ({ client, connection } = await verifiedClient(
      origin,
      signal,
      state,
      authorizer,
    ));
    const authority = await walletSession.authorizeTvcWallet({
      servicePublicKey: PRIVATE_WALLET_SERVICE_PUBLIC_KEY,
    });
    if (!sameAuthority(state.tvcAuthority, authority)) {
      throw new Error("TvcAuthorityMismatch");
    }
  } else {
    // Verify the live deployment before granting its pinned service key any
    // authority in the public wallet's Turnkey organization.
    await verifiedClient(origin, signal);
    const authority = await walletSession.authorizeTvcWallet({
      servicePublicKey: PRIVATE_WALLET_SERVICE_PUBLIC_KEY,
    });
    signal.throwIfAborted();
    state = await enrollDevice(
      origin,
      walletSession,
      wallet,
      authorizer,
      authority,
      signal,
    );
    ({ client, connection } = await verifiedClient(
      origin,
      signal,
      state,
      authorizer,
    ));
  }

  state = await ensureIdentity(
    state,
    client,
    connection,
    input.withBootstrapApproval,
    signal,
  );
  if (!state.identity || !state.sealedSeed) {
    throw new Error("PrivateWalletIdentityUnavailable");
  }
  const keys = revocableWalletKeys(
    new TvcKeys({
      client,
      connection,
      identity: state.identity,
      sealedSeed: state.sealedSeed,
      // The enclave seals each proof for its route below the prover URL;
      // this host's route handler forwards it untouched.
      prover: {
        url: `${origin}/api/tvc/zolana/prover`,
        policy: DEVNET_PROVER_POLICY,
      },
    }),
    signal,
  );
  const zolana = await createPrivateZolanaClient(origin, input.solanaRpcUrl);
  signal.throwIfAborted();
  return Object.freeze({
    ownerAddress: address(wallet.address),
    keys,
    zolana,
  });
}
