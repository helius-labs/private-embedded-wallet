/**
 * The operator's side: wallet descriptors signed with the provisioning key the
 * enclave pins. A wallet client never holds this key.
 */
export {
  DEVELOPMENT_PROVISIONING_PUBLIC_KEY,
  provisioningSecret,
  signWalletDescriptor,
  type WalletDescriptorInput,
} from "./protocol/provisioning.js";
