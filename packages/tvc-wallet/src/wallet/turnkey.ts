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
import type { SprEmbeddedWalletTransport } from "../client/transport.js";
import { createSprRequestSigner } from "../platform/signer.js";
import { API_VERSION } from "../protocol/constants.js";
import { decodeDecimalU64 } from "../protocol/decimal.js";
import { clientKeyIdFor } from "../protocol/digest.js";
import { ENROLLMENT_DOMAINS, walletEnrollmentMessage } from "../protocol/enrollment.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type { Network, WalletDescriptor } from "../protocol/types.js";
import type { SprEmbeddedWalletClientKey, SprEmbeddedWalletClientKeys } from "./client-keys.js";

/** The active Turnkey session, as `getSession` answers it. */
export type SprEmbeddedWalletTurnkeySession = {
  /**
   * The session's P-256 public key, compressed SEC1 hex. It is the client key:
   * it signs every request, and the client enrolls it with the gateway.
   */
  readonly publicKey?: string | undefined;
  /** The sub-organization that holds the wallet. */
  readonly organizationId: string;
};

/** A wallet account, as `fetchWallets` lists it. */
export type SprEmbeddedWalletTurnkeyWalletAccount = {
  readonly address: string;
  readonly addressFormat: string;
  /** `connected` for an external wallet, such as a browser extension, which cannot be enrolled. */
  readonly source?: string;
};

/** A wallet and its accounts, as `fetchWallets` lists it. */
export type SprEmbeddedWalletTurnkeyWallet<Account extends SprEmbeddedWalletTurnkeyWalletAccount = SprEmbeddedWalletTurnkeyWalletAccount> = {
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
export type SprEmbeddedWalletTurnkey<Account extends SprEmbeddedWalletTurnkeyWalletAccount = SprEmbeddedWalletTurnkeyWalletAccount> = {
  /** The active session, or `undefined` when nobody is logged in. */
  getSession(): Promise<SprEmbeddedWalletTurnkeySession | undefined>;
  /**
   * ECDSA P-256 over SHA-256 of `message`'s UTF-8 bytes, with the session key
   * `publicKey` names, as compact `r || s` hex.
   */
  signWithApiKey(params: { message: string; publicKey: string }): Promise<string>;
  /** The session organization's wallets and their accounts. */
  fetchWallets(): Promise<readonly SprEmbeddedWalletTurnkeyWallet<Account>[]>;
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

export type TurnkeyClientKeysConfig<Account extends SprEmbeddedWalletTurnkeyWalletAccount> = {
  readonly turnkey: SprEmbeddedWalletTurnkey<Account>;
  readonly network: Network;
  /** The tvc-gateway; the owner signs the enrollment for its host. */
  readonly endpoint: URL;
  /** Names the wallet account when the organization holds more than one Solana account. */
  readonly solanaAddress?: string;
  readonly transport: SprEmbeddedWalletTransport;
  readonly nowMs: () => bigint;
};

const SOLANA = "ADDRESS_FORMAT_SOLANA";
const MAX_ENROLLMENT_RESPONSE_BYTES = 64n * 1024n;
/** Bounds `POST /enroll` once the owner signed, when no caller's signal does. */
const SIGNED_ENROLLMENT_TIMEOUT_MS = 60_000;
/** A descriptor that expires within this is enrolled again before the next request. */
export const DESCRIPTOR_RENEWAL_MARGIN_MS = 300_000n;
const DESCRIPTOR_KEYS = [
  "version",
  "security_domain_id",
  "network",
  "turnkey_organization_id",
  "turnkey_wallet_id",
  "address",
  "allowed_clients",
  "expires_at_ms",
  "provisioning_signature",
] as const;
const CLIENT_GRANT_KEYS = ["client_public_key", "allowed_operations"] as const;

/** One enrollment, shared by every caller waiting for it. */
type Enrollment = {
  readonly controller: AbortController;
  readonly promise: Promise<OperationsConfig>;
  waiters: number;
  /** The owner signed it: it finishes, and its descriptor is kept, whoever still waits. */
  signed: boolean;
};

/**
 * The tail of each Turnkey client's `signWithApiKey` calls. `@turnkey/core`
 * 2.7.1 sets the stamper's temporary public key for the call and restores the
 * one it found when the call ends, so two overlapping calls can restore the
 * first call's key last and leave the application's stamper pinned to it.
 */
const apiKeySignatures = new WeakMap<object, Promise<void>>();

/** `sign` once every earlier `signWithApiKey` call of the client on `turnkey` has ended. */
function signingAlone<T>(turnkey: object, sign: () => Promise<T>): Promise<T> {
  const turn = (apiKeySignatures.get(turnkey) ?? Promise.resolve()).then(sign);
  apiKeySignatures.set(turnkey, turn.then(() => undefined, () => undefined));
  return turn;
}

/** The uncompressed SEC1 form of a Turnkey session key, which descriptors list. */
function uncompressedSessionKey(publicKey: string): Uint8Array {
  try {
    return p256.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  } catch {
    throw new SprEmbeddedWalletError("InvalidPublicKey", "the Turnkey session key is not a P-256 public key");
  }
}

function hexSignature(value: string): Uint8Array {
  try {
    return decodeLowerHex(value.replace(/^0x/u, "").toLowerCase());
  } catch {
    throw new SprEmbeddedWalletError("InvalidSignatureEncoding");
  }
}

/** The wallet account to enroll: the one named, or the organization's only embedded Solana account. */
async function walletAccount<Account extends SprEmbeddedWalletTurnkeyWalletAccount>(
  turnkey: SprEmbeddedWalletTurnkey<Account>,
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
    throw new SprEmbeddedWalletError(
      "WalletAccountNotFound",
      solanaAddress === undefined
        ? "the Turnkey organization holds no Solana wallet account"
        : `the Turnkey organization holds no wallet account ${solanaAddress}`,
    );
  }
  if (others.length > 0) {
    throw new SprEmbeddedWalletError("WalletAccountAmbiguous", "name the wallet's Solana address with solanaAddress");
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
  if (typeof descriptor.expires_at_ms !== "string") {
    throw new SprEmbeddedWalletError("InvalidDescriptor", "the descriptor names no expiry");
  }
  decodeDecimalU64(descriptor.expires_at_ms);
  if (
    others.length > 0 ||
    descriptor.version !== API_VERSION ||
    descriptor.network !== expected.network ||
    descriptor.turnkey_organization_id !== expected.organizationId ||
    descriptor.turnkey_wallet_id !== expected.walletId ||
    descriptor.address !== expected.address ||
    grant?.client_public_key !== expected.clientPublicKey
  ) {
    throw new SprEmbeddedWalletError("InvalidDescriptor", "the gateway answered a descriptor for another wallet or key");
  }
  return Object.freeze(descriptor);
}

/**
 * The Turnkey session key as the client key. Each session key is enrolled once,
 * on first use: the wallet owner signs the enrollment through Turnkey and the
 * gateway answers its descriptor, which the client keeps in memory for that
 * key. A new login brings a new session key, which is enrolled in turn.
 */
export function turnkeyClientKeys<Account extends SprEmbeddedWalletTurnkeyWalletAccount>(
  config: TurnkeyClientKeysConfig<Account>,
): SprEmbeddedWalletClientKeys {
  const { turnkey, network, endpoint, solanaAddress, transport, nowMs } = config;
  const keys = new Map<string, SprEmbeddedWalletClientKey>();

  /**
   * Enrolls `clientPublicKey`. `signal` stops it until the owner has signed;
   * from `onSigned` on it runs to the end, so the owner's signature is never
   * wasted.
   */
  async function enroll(
    session: { readonly publicKey: string; readonly organizationId: string },
    clientPublicKey: string,
    signal: AbortSignal,
    onSigned: () => void,
  ): Promise<WalletDescriptor> {
    const { walletId, account } = await walletAccount(turnkey, solanaAddress, signal);
    const enrollment = {
      organizationId: session.organizationId,
      turnkeyWalletId: walletId,
      solanaAddress: account.address,
      clientPublicKey,
      issuedAtMs: Number(nowMs()),
    };
    const signing = turnkey.signMessage({
      message: walletEnrollmentMessage({ domain: ENROLLMENT_DOMAINS[network], network, ...enrollment }),
      walletAccount: account,
      encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
      hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
    });
    // Before any other reaction to the signature, so no abort follows it.
    void signing.then(onSigned, () => undefined);
    const signed = await awaitWithSignal(signing, signal);
    const posting = AbortSignal.timeout(SIGNED_ENROLLMENT_TIMEOUT_MS);
    const ownerSignature = `${signed.r.padStart(64, "0")}${signed.s.padStart(64, "0")}`.toLowerCase();
    if (!/^[0-9a-f]{128}$/u.test(ownerSignature)) throw new SprEmbeddedWalletError("InvalidSignatureEncoding");
    const response = await fetchWithSignal(transport, gatewayUrl(endpoint, "enroll"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...enrollment, ownerSignature }),
    }, posting);
    if (!response.ok) throw httpError(response, "EnrollmentRejected");
    return enrolledDescriptor(await readBoundedText(response, MAX_ENROLLMENT_RESPONSE_BYTES, posting), {
      network,
      organizationId: session.organizationId,
      walletId,
      address: account.address,
      clientPublicKey,
    });
  }

  function sessionKey(session: { readonly publicKey: string; readonly organizationId: string }): SprEmbeddedWalletClientKey {
    const clientPublicKey = encodeLowerHex(uncompressedSessionKey(session.publicKey));
    const clientKeyId = clientKeyIdFor(decodeLowerHex(clientPublicKey));
    const signer = createSprRequestSigner({
      clientKeyId,
      sign: async (message) =>
        hexSignature(
          await signingAlone(turnkey, () => turnkey.signWithApiKey({ message, publicKey: session.publicKey })),
        ),
    });
    let enrolled: OperationsConfig | undefined;
    let pending: Enrollment | undefined;
    /** Whether `config`'s descriptor still has the renewal margin ahead of it. */
    const current = (config: OperationsConfig) =>
      BigInt(config.descriptor.expires_at_ms) - nowMs() > DESCRIPTOR_RENEWAL_MARGIN_MS;

    const start = (): Enrollment => {
      const controller = new AbortController();
      const flight: Enrollment = {
        controller,
        waiters: 0,
        signed: false,
        promise: enroll(session, clientPublicKey, controller.signal, () => {
          flight.signed = true;
        })
          .then((descriptor) => {
            // Kept even when every caller left: the owner signed it.
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
      // its own wait. Once nobody waits the enrollment stops, unless the owner
      // already signed it: then it finishes, and later callers share it.
      async operations(signal) {
        signal?.throwIfAborted();
        if (enrolled && current(enrolled)) return enrolled;
        enrolled = undefined;
        const flight = (pending ??= start());
        flight.waiters += 1;
        try {
          return await awaitWithSignal(flight.promise, signal);
        } finally {
          flight.waiters -= 1;
          if (flight.waiters === 0 && pending === flight && !flight.signed) {
            pending = undefined;
            flight.controller.abort(signal?.reason);
          }
        }
      },
      expire(descriptor) {
        if (enrolled?.descriptor === descriptor) enrolled = undefined;
      },
    };
  }

  return {
    ...(solanaAddress === undefined ? {} : { solanaAddress }),
    async current(signal) {
      const session = await awaitWithSignal(turnkey.getSession(), signal);
      const publicKey = session?.publicKey;
      if (!session || !publicKey) {
        throw new SprEmbeddedWalletError("TurnkeySessionRequired", "no active Turnkey session: log in first");
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
