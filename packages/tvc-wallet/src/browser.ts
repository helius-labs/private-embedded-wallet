export { loadOrCreatePersistentBrowserTvcSigner } from "./platform/browser-signer.js";
export type {
  PersistentBrowserTvcSigner,
  PersistentBrowserTvcSignerOptions,
} from "./platform/browser-signer.js";
export {
  parsePersistentBrowserTvcWalletState,
  parseShieldedIdentity,
} from "./platform/browser-state.js";
export type { PersistentBrowserTvcWalletState } from "./platform/browser-state.js";
export {
  clearRecord,
  hasOnlyKeys,
  loadRecord,
  saveRecord,
} from "./platform/persisted-state.js";
