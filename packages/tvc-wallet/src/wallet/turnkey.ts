import { p256 } from "@noble/curves/p256";

import {
  assertExactObjectKeys,
  fetchWithSignal,
  gatewayUrl,
  httpError,
  readBoundedText,
} from "../client/http.js";
import type { OperationsConfig } from "../client/operation-executor.js";
import { awaitWithSignal } from "../client/request.js";
import type { TvcTransport } from "../client/transport.js";
import { createTvcRequestSigner } from "../platform/signer.js";
import { API_VERSION } from "../protocol/constants.js";
import { clientKeyIdFor } from "../protocol/digest.js";
import { ENROLLMENT_DOMAINS, walletEnrollmentMessage } from "../protocol/enrollment.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type { Network, WalletDescriptor } from "../protocol/types.js";
import type { TvcClientKey, TvcClientKeys } from "./client-keys.js";

/** The active Turnkey session, as `getSession` answers it. */
export type TvcTurnkeySession = {
  /**
   * The session's P-256 public key, compressed SEC1 hex. It is the client key:
   * it signs every request, and the client enrolls it with the gateway.
   */
  readonly publicKey?: string | undefined;
  /** The sub-organization that holds the wallet. */
  readonly organizationId: string;
};

/** A wallet account, as `fetchWallets` lists it. */
export type TvcTurnkeyWalletAccount = {
  readonly address: string;
  readonly addressFormat: string;
  /** `connected` for an external wallet, such as a browser extension, which cannot be enrolled. */
  readonly source?: string;
};

/** A wallet and its accounts, as `fetchWallets` lists it. */
export type TvcTurnkeyWallet<Account extends TvcTurnkeyWalletAccount = TvcTurnkeyWalletAccount> = {
  readonly walletId: string;
  readonly accounts: readonly Account[];
};

/**
 * What the client needs from the application's Turnkey client.
 * `@turnkey/core`'s `TurnkeyClient`, and what `useTurnkey()` returns in
 * `@turnkey/react-wallet-kit`, are one as they are. A server implements it
 * over an API key: the session key is the API key, `signWithApiKey` signs with
 * its private half, and `signMessage` is `signRawPayload`.
 */
export type TvcTurnkey<Account extends TvcTurnkeyWalletAccount = TvcTurnkeyWalletAccount> = {
  /** The active session, or `undefined` when nobody is logged in. */
  getSession(): Promise<TvcTurnkeySession | undefined>;
  /**
   * ECDSA P-256 over SHA-256 of `message`'s UTF-8 bytes, with the session key
   * `publicKey` names, as compact `r || s` hex.
   */
  signWithApiKey(params: { message: string; publicKey: string }): Promise<string>;
  /** The session organization's wallets and their accounts. */
  fetchWallets(): Promise<readonly TvcTurnkeyWallet<Account>[]>;
  /**
   * The wallet account's Ed25519 signature over `message`'s UTF-8 bytes,
   * unhashed. `walletAccount` is one `fetchWallets` listed.
   */
  signMessage(params: {
    message: string;
    walletAccount: Account;
    encoding: "PAYLOAD_ENCODING_TEXT_UTF8";
    hashFunction: "HASH_FUNCTION_NOT_APPLICABLE";
  }): Promise<{ readonly r: string; readonly s: string }>;
};

export type TurnkeyClientKeysConfig<Account extends TvcTurnkeyWalletAccount> = {
  readonly turnkey: TvcTurnkey<Account>;
  readonly network: Network;
  /** The tvc-gateway; the owner signs the enrollment for its host. */
  readonly endpoint: URL;
  /** Names the wallet account when the organization holds more than one Solana account. */
  readonly solanaAddress?: string;
  readonly transport: TvcTransport;
  readonly nowMs: () => bigint;
};

const SOLANA = "ADDRESS_FORMAT_SOLANA";
const MAX_ENROLLMENT_RESPONSE_BYTES = 64n * 1024n;
const DESCRIPTOR_KEYS = [
  "version",
  "security_domain_id",
  "network",
  "turnkey_organization_id",
  "turnkey_wallet_id",
  "address",
  "allowed_clients",
  "provisioning_signature",
] as const;
const CLIENT_GRANT_KEYS = ["client_public_key", "allowed_operations"] as const;

/** One enrollment, shared by every caller waiting for it. */
type Enrollment = {
  readonly controller: AbortController;
  readonly promise: Promise<OperationsConfig>;
  waiters: number;
};

/** The uncompressed SEC1 form of a Turnkey session key, which descriptors list. */
function uncompressedSessionKey(publicKey: string): Uint8Array {
  try {
    return p256.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  } catch {
    throw new TvcError("InvalidPublicKey", "the Turnkey session key is not a P-256 public key");
  }
}

function hexSignature(value: string): Uint8Array {
  try {
    return decodeLowerHex(value.replace(/^0x/u, "").toLowerCase());
  } catch {
    throw new TvcError("InvalidSignatureEncoding");
  }
}

/** The wallet account to enroll: the one named, or the organization's only embedded Solana account. */
async function walletAccount<Account extends TvcTurnkeyWalletAccount>(
  turnkey: TvcTurnkey<Account>,
  solanaAddress: string | undefined,
  signal?: AbortSignal,
): Promise<{ readonly walletId: string; readonly account: Account }> {
  const wallets = await awaitWithSignal(turnkey.fetchWallets(), signal);
  const candidates = wallets.flatMap(({ walletId, accounts }) =>
    accounts
      .filter((account) => account.addressFormat === SOLANA && account.source !== "connected")
      .filter((account) => solanaAddress === undefined || account.address === solanaAddress)
      .map((account) => ({ walletId, account })),
  );
  const [only, ...others] = candidates;
  if (only === undefined) {
    throw new TvcError(
      "WalletAccountNotFound",
      solanaAddress === undefined
        ? "the Turnkey organization holds no Solana wallet account"
        : `the Turnkey organization holds no wallet account ${solanaAddress}`,
    );
  }
  if (others.length > 0) {
    throw new TvcError("WalletAccountAmbiguous", "name the wallet's Solana address with solanaAddress");
  }
  return only;
}

/** The descriptor the gateway answered, checked to list this key for this wallet on this network. */
function enrolledDescriptor(
  text: string,
  expected: {
    readonly network: Network;
    readonly organizationId: string;
    readonly walletId: string;
    readonly address: string;
    readonly clientPublicKey: string;
  },
): WalletDescriptor {
  const { descriptor } = parseStrictJson<{ descriptor: WalletDescriptor }>(text, ["descriptor"]);
  assertExactObjectKeys(descriptor, DESCRIPTOR_KEYS, "InvalidDescriptor");
  const [grant, ...others] = Array.isArray(descriptor.allowed_clients) ? descriptor.allowed_clients : [];
  assertExactObjectKeys(grant, CLIENT_GRANT_KEYS, "InvalidDescriptor");
  if (
    others.length > 0 ||
    descriptor.version !== API_VERSION ||
    descriptor.network !== expected.network ||
    descriptor.turnkey_organization_id !== expected.organizationId ||
    descriptor.turnkey_wallet_id !== expected.walletId ||
    descriptor.address !== expected.address ||
    grant?.client_public_key !== expected.clientPublicKey
  ) {
    throw new TvcError("InvalidDescriptor", "the gateway answered a descriptor for another wallet or key");
  }
  return Object.freeze(descriptor);
}

/**
 * The Turnkey session key as the client key. Each session key is enrolled once,
 * on first use: the wallet owner signs the enrollment through Turnkey and the
 * gateway answers its descriptor, which the client keeps in memory for that
 * key. A new login brings a new session key, which is enrolled in turn.
 */
export function turnkeyClientKeys<Account extends TvcTurnkeyWalletAccount>(
  config: TurnkeyClientKeysConfig<Account>,
): TvcClientKeys {
  const { turnkey, network, endpoint, solanaAddress, transport, nowMs } = config;
  const keys = new Map<string, TvcClientKey>();

  async function enroll(
    session: { readonly publicKey: string; readonly organizationId: string },
    clientPublicKey: string,
    signal: AbortSignal,
  ): Promise<WalletDescriptor> {
    const { walletId, account } = await walletAccount(turnkey, solanaAddress, signal);
    const enrollment = {
      organizationId: session.organizationId,
      turnkeyWalletId: walletId,
      solanaAddress: account.address,
      clientPublicKey,
      issuedAtMs: Number(nowMs()),
    };
    const signed = await awaitWithSignal(
      turnkey.signMessage({
        message: walletEnrollmentMessage({ domain: ENROLLMENT_DOMAINS[network], network, ...enrollment }),
        walletAccount: account,
        encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
        hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
      }),
      signal,
    );
    const ownerSignature = `${signed.r.padStart(64, "0")}${signed.s.padStart(64, "0")}`.toLowerCase();
    if (!/^[0-9a-f]{128}$/u.test(ownerSignature)) throw new TvcError("InvalidSignatureEncoding");
    const response = await fetchWithSignal(transport, gatewayUrl(endpoint, "enroll"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...enrollment, ownerSignature }),
    }, signal);
    if (!response.ok) throw httpError(response, "EnrollmentRejected");
    return enrolledDescriptor(await readBoundedText(response, MAX_ENROLLMENT_RESPONSE_BYTES, signal), {
      network,
      organizationId: session.organizationId,
      walletId,
      address: account.address,
      clientPublicKey,
    });
  }

  function sessionKey(session: { readonly publicKey: string; readonly organizationId: string }): TvcClientKey {
    const clientPublicKey = encodeLowerHex(uncompressedSessionKey(session.publicKey));
    const clientKeyId = clientKeyIdFor(decodeLowerHex(clientPublicKey));
    const signer = createTvcRequestSigner({
      clientKeyId,
      sign: async (message) =>
        hexSignature(await turnkey.signWithApiKey({ message, publicKey: session.publicKey })),
    });
    let enrolled: OperationsConfig | undefined;
    let pending: Enrollment | undefined;

    const start = (): Enrollment => {
      const controller = new AbortController();
      const flight: Enrollment = {
        controller,
        waiters: 0,
        promise: enroll(session, clientPublicKey, controller.signal)
          .then((descriptor) => {
            // Kept even when every caller left: the owner already signed it.
            enrolled = Object.freeze({ descriptor, signer });
            return enrolled;
          })
          .finally(() => {
            if (pending === flight) pending = undefined;
          }),
      };
      return flight;
    };

    return {
      id: session.publicKey,
      // Concurrent first calls share one enrollment; each caller can abandon
      // its own wait, and the enrollment stops once nobody waits for it.
      async operations(signal) {
        signal?.throwIfAborted();
        if (enrolled) return enrolled;
        const flight = (pending ??= start());
        flight.waiters += 1;
        try {
          return await awaitWithSignal(flight.promise, signal);
        } finally {
          flight.waiters -= 1;
          if (flight.waiters === 0 && pending === flight) {
            pending = undefined;
            flight.controller.abort(signal?.reason);
          }
        }
      },
    };
  }

  return {
    ...(solanaAddress === undefined ? {} : { solanaAddress }),
    async current(signal) {
      const session = await awaitWithSignal(turnkey.getSession(), signal);
      const publicKey = session?.publicKey;
      if (!session || !publicKey) {
        throw new TvcError("TurnkeySessionRequired", "no active Turnkey session: log in first");
      }
      let key = keys.get(publicKey);
      if (!key) {
        key = sessionKey({ publicKey, organizationId: session.organizationId });
        keys.set(publicKey, key);
      }
      return key;
    },
  };
}
