/**
 * The operator's side: wallet descriptors and wallet grants signed with the
 * keys the enclave pins. A wallet client never holds these keys.
 */
export {
  DEVELOPMENT_PROVISIONING_PUBLIC_KEY,
  provisioningSecret,
  signWalletDescriptor,
  type WalletDescriptorInput,
} from "./protocol/provisioning.js";
export {
  DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY,
  MAX_WALLET_GRANT_LIFETIME_MS,
  signWalletGrant,
  walletGrantSecret,
  type WalletGrantInput,
} from "./protocol/grant.js";
