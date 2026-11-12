# Decryption-service TVC application

Prototype of the [decryption service](../../crates/protocol/README.md#decryption-service):
private transfers to a Solana address before its owner registers a wallet.

1. A bootstrap release, started without `--seed-commitment`, runs `Genesis`
   and then `Backup`. Each holder keeps their share.
2. The serving release pins the seed's commitment with `--seed-commitment`.
   It opens only that seed, and clients send its sealed form with each
   request.
3. A sender calls `PublicKeys` for an address and encrypts a transfer to the
   keys it returns.
4. The owner signs a `Decrypt` request with the address. The enclave opens
   every output in it with the service viewing key and returns the plaintexts
   and the service nullifier secret. The client keeps a plaintext only when
   its commitment equals the indexed one.

Under a new Quorum key, enough holders hand their shares to `Restore`, which
seals the same seed again. A lost holder is replaced by a release that names
a new holder set and a fresh `Backup`; the old holders then destroy their
shares.

It is its own application, apart from the privacy wallet: its own Quorum key,
release and `/v1/info`. The two share
[`crates/enclave`](../../crates/enclave): the routes, the request envelope,
the proof-carrying response and the pool cipher.

Module map: `operations.rs` (the operations and which a release serves),
`keys.rs` (the derivation and the seed commitment), `seed.rs` (the sealed
master seed), `custody.rs` (the pinned commitment and the backup holders),
`backup.rs` (splitting and rebuilding the seed), `owner.rs` (which addresses
have keys, the owner's signature). It reaches no service.

```sh
cargo test -p spr-tvc-decryption-service
```

The tests decrypt an output encrypted as a sender encrypts it.

Not there yet:

- An enclave image, a release policy and a Turnkey application.
- A local testkit binary, a gateway route and a client.
- The backup holders and their keys; the tests use generated ones.
