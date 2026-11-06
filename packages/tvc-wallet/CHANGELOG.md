# Changelog

## 0.1.0-alpha — unreleased

The first release. The client verifies the private-wallet enclave of a
network against the release this package pins, enrolls the user's Turnkey
session key with the Helius gateway, and answers the `@heliuslabs/spr` 0.9
SDK's `WalletKeys` from the enclave. It pins a devnet release only, and is
ESM only.

Added

- `createSprEmbeddedWallet({ network, endpoint, turnkey })` reaches the network's private wallet through Helius or an application's route and signs every request with the logged-in Turnkey session key.
- `SprEmbeddedWallet.open(stored, { approve })` bootstraps a wallet once with the owner's approval and reopens it from `keys.stored` without a call.
- `SprEmbeddedWalletKeys` is the SDK's `WalletKeys`, so `syncWallet`, `buildTransferTransaction` and the other SDK flows run with the enclave's keys.
- `parseStoredWallet(value)` reads `keys.stored` back from storage and refuses anything else.
- `snapshotCipher(keys)` encrypts wallet snapshots for `syncPersistedWallet` and `loadPersistedWallet`.
- `SprEmbeddedWalletHttpError` keeps the `status` and `retryAfter` of an HTTP failure, and `SprEmbeddedWalletOperationError` names the `operation` and `stage` of an operation that failed in the enclave.
- `@heliuslabs/spr-embedded-wallet/protocol` exports the wire types, `SprEmbeddedWalletError` and `walletEnrollmentMessage`.
- `@heliuslabs/spr-embedded-wallet/testing` exports `createTestSprEmbeddedWallet` for a test deployment and `createLocalSprEmbeddedWallet` for the unattested local testkit.
