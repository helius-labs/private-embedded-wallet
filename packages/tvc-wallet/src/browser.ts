export { loadOrCreatePersistentBrowserTvcAuthorizer } from "./platform/browser-authorizer.js";
export type {
  PersistentBrowserTvcAuthorizer,
  PersistentBrowserTvcAuthorizerOptions,
} from "./platform/browser-authorizer.js";
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
