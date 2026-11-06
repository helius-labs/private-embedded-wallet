export {
  sealedSeedOf,
  createTvcClient,
  identityOf,
  type BootstrapOptions,
  type ShieldedIdentity,
  type TvcClient,
  type TvcClientConfig,
} from "./wallet/client.js";
export { shieldedAddressOf } from "./wallet/identity.js";
export { TvcKeys, type TvcKeysInput } from "./wallet/keys.js";
export { type TvcProverConfig } from "./wallet/prover.js";
export { RELEASES, releaseFor, type ReleaseTrust } from "./protocol/releases.js";
export { TvcProverPolicy, type HeldProverPolicy } from "./wallet/prover-policy.js";
export { snapshotCipher } from "./wallet/snapshot.js";
export type { OperationOptions } from "./wallet/operations.js";
export type {
  BootProofResolver,
  EnclaveBackend,
  GatewayBackend,
  ResolveBootProofInput,
  TvcBackend,
} from "./client/backend.js";
export type { VerifiedConnection } from "./client/connection.js";
export type { OperationsConfig, TvcOperationAuthorizer } from "./client/operation-executor.js";
export { createTvcOperationAuthorizer, type TvcRequestSigner } from "./platform/authorizer.js";
export type { TvcTransport } from "./client/transport.js";
export type { QosIdentityPcrs } from "./verify/index.js";
export type { TvcRequestOptions } from "./client/request.js";
export { TvcHttpError } from "./protocol/error.js";
export type { Network } from "./protocol/types.js";
