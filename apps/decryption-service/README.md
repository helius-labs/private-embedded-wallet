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
```

The tests decrypt an output encrypted as a sender encrypts it.

Not there yet:

- An enclave image, a release policy and a Turnkey application with a local
  Quorum key and its operators.
- A local testkit binary, a gateway route and a client.
