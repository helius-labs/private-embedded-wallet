export {
  createSprEmbeddedWallet,
  type ShieldedIdentity,
  type StoredWallet,
  type SprEmbeddedWallet,
  type SprEmbeddedWalletConfig,
  type SprEmbeddedWalletOpenOptions,
} from "./wallet/client.js";
export type {
  SprEmbeddedWalletTurnkey,
  SprEmbeddedWalletTurnkeySession,
  SprEmbeddedWalletTurnkeyWallet,
  SprEmbeddedWalletTurnkeyWalletAccount,
} from "./wallet/turnkey.js";
export { parseStoredWallet } from "./wallet/stored.js";
export type { SprEmbeddedWalletKeys } from "./wallet/keys.js";
export { snapshotCipher } from "./wallet/snapshot.js";
export type { SprEmbeddedWalletTransport } from "./client/transport.js";
export type { SprEmbeddedWalletRequestOptions } from "./client/request.js";
export { SprEmbeddedWalletHttpError, SprEmbeddedWalletOperationError } from "./protocol/error.js";
export type { Network } from "./protocol/types.js";
