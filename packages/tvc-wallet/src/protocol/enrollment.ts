import { TvcError } from "./error.js";
import { requireNetwork } from "./network.js";
import type { Network } from "./types.js";

/** The statement of the Sign-In With Solana message that enrolls a client key with tvc-gateway. */
export const WALLET_ENROLLMENT_STATEMENT = "Authorize this client key to use your private wallet.";
const ENROLLMENT_LIFETIME_MS = 5 * 60 * 1_000;
/** `9999-12-31T23:59:59.999Z`, the last instant with a four-digit year, less the lifetime. */
const MAX_ISSUED_AT_MS = 253_402_300_799_999 - ENROLLMENT_LIFETIME_MS;

/** `POST /enroll`, less the owner's signature over {@link walletEnrollmentMessage}. */
export type WalletEnrollment = {
  /** The host of the gateway endpoint, such as `beta-devnet.helius-rpc.com`. It is not sent. */
  readonly domain: string;
  /** The network the gateway serves, the message's chain. It is not sent. */
  readonly network: Network;
  readonly organizationId: string;
  readonly turnkeyWalletId: string;
  readonly solanaAddress: string;
  /** Uncompressed SEC1 P-256 key, lowercase hex. */
  readonly clientPublicKey: string;
  readonly issuedAtMs: number;
};

/**
 * The Sign-In With Solana message the wallet owner signs with Ed25519, through
 * Turnkey, to enroll `clientPublicKey` at the gateway on `domain`, which serves
 * `network`. It is valid for five minutes from `issuedAtMs`.
 */
export function walletEnrollmentMessage(enrollment: WalletEnrollment): string {
  const { issuedAtMs } = enrollment;
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 || issuedAtMs > MAX_ISSUED_AT_MS) {
    throw new TvcError("InvalidDecimal", "issuedAtMs must be a time in milliseconds");
  }
  const network = requireNetwork(enrollment.network);
  const fields = [
    enrollment.domain,
    enrollment.organizationId,
    enrollment.turnkeyWalletId,
    enrollment.solanaAddress,
    enrollment.clientPublicKey,
  ];
  if (fields.some((field) => /[\r\n]/u.test(field))) {
    throw new TvcError("InvalidDescriptor", "enrollment fields cannot contain a line break");
  }
  return [
    `${enrollment.domain} wants you to sign in with your Solana account:`,
    enrollment.solanaAddress,
    "",
    WALLET_ENROLLMENT_STATEMENT,
    "",
    "Version: 1",
    `Chain ID: ${network}`,
    `Issued At: ${new Date(issuedAtMs).toISOString()}`,
    `Expiration Time: ${new Date(issuedAtMs + ENROLLMENT_LIFETIME_MS).toISOString()}`,
    "Resources:",
    `- urn:turnkey:organization:${enrollment.organizationId}`,
    `- urn:turnkey:wallet:${enrollment.turnkeyWalletId}`,
    `- urn:zolana-tvc:client-key:${enrollment.clientPublicKey}`,
  ].join("\n");
}
