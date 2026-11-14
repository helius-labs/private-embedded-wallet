# Decryption-service TVC application

Prototype of the decryption service: private transfers to a Solana address
before its owner registers a wallet. [`SPEC.md`](SPEC.md) is the design;
[`crates/protocol`](../../crates/protocol/README.md#decryption-service) has
the encoding.

1. A sender calls `PublicKeys` for an address and encrypts a transfer to the
   keys it returns.
2. The owner signs a `Decrypt` request with the address. The enclave opens
   every output in it with the service viewing key and returns the plaintexts
   and the service nullifier secret. The client keeps a plaintext only when
   its commitment equals the indexed one.

The master seed derives from the Quorum key, so it lives and is recovered with
it. The app's Quorum key is meant to be a local one: generated offline with
`tvc keys generate-local-quorum-key`, split 2-of-3 among YubiKey operators,
with the encrypted shares in `quorum_key_metadata.json` kept outside Turnkey.
Each release is provisioned with `tvc keys re-encrypt-local-share` and
`tvc deploy post-share`. Changing the share set means rebuilding the Quorum
key offline and splitting it again; no tool does that yet.

It is its own application, apart from the privacy wallet: its own Quorum key,
release and `/v1/info`. The two share
[`crates/enclave`](../../crates/enclave): the routes, the request envelope,
the proof-carrying response and the pool cipher.

Module map: `operations.rs` (the two operations), `keys.rs` (the master seed
and the service keys), `owner.rs` (which addresses have keys, the owner's
signature). It reaches no service.

```sh
cargo test -p spr-tvc-decryption-service
cargo run -p spr-tvc-decryption-service --features local-dev --bin spr-tvc-decryption-service-local
```

The tests decrypt an output encrypted as a sender encrypts it. The second
command is the unattested local testkit on `127.0.0.1:44030`, under the same
pinned keys as the privacy wallet's.

The client is `@heliuslabs/spr-embedded-wallet/decryption-service`
([`packages/tvc-wallet`](../../packages/tvc-wallet/README.md#decryption-service)).
`just headless-e2e` runs
[`unregistered_recipient.ts`](../../examples/typescript-client/examples/unregistered_recipient.ts)
against the testkit: a transfer to an address without a wallet, opened through
the service and swept to the owner's own wallet.

Devnet has a Turnkey application,
[`spr-decryption-service-devnet`](deploy/devnet/spr-decryption-service-devnet.app.json),
with a local Quorum key split 2-of-3 among three operator key files, which
stand in for YubiKeys there. [`scripts/release.mjs`](../../scripts/README.md#release)
releases it with `--app decryption-service`.

Devnet clients reach it through tvc-gateway at `/v1/decryption-service` with a
Helius API key only (Boot Proofs beside session and operations). Direct enclave
access still needs a Turnkey API key of the application's organization for Boot
Proofs.
