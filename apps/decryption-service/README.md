# Decryption-service TVC application

Prototype. Lets a Solana address receive private transfers before its owner
registers a wallet. The enclave derives one viewing key and one nullifier key
per address, its service keys, from a master seed sealed to the Quorum key,
and never releases the viewing secret. The requests, results and signed
message are specified in
[`crates/protocol`](../../crates/protocol/README.md#decryption-service).

1. An operator runs `Genesis` once and publishes the sealed master seed. Every
   later request presents it.
2. A sender calls `PublicKeys` for an address and encrypts a transfer to the
   keys it returns.
3. The owner signs a `Decrypt` request with the address. The enclave opens
   every output in it with the service viewing key and returns the plaintexts
   and the service nullifier secret. The client keeps a plaintext only when
   its commitment equals the indexed one.

It is its own application, apart from the privacy wallet: its own Quorum key,
release and `/v1/info`. The two share
[`crates/enclave`](../../crates/enclave): the routes, the request envelope,
the proof-carrying response and the pool cipher.

Module map: `operations.rs` (the three operations), `keys.rs` (the
derivation), `seed.rs` (the master seed, encrypted to the Quorum key and
signed by it), `owner.rs` (which addresses have keys, the owner's signature).
It reaches no service.

```sh
cargo test -p spr-tvc-decryption-service
```

The tests decrypt an output encrypted as a sender encrypts it.

Not there yet:

- An enclave image, a release policy and a Turnkey application.
- A local testkit binary, a gateway route and a client.
- A copy of the master seed outside the Quorum key, and a release step that
  pins the result of `Genesis`.
