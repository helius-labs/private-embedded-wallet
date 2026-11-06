# Privacy-wallet TVC application

Holds the wallet's privacy roles (nullifier key and viewing key, expanded from a
Turnkey-derived seed) out of browser JavaScript. Replica-stateless: the client
carries the seed sealed to the QOS Quorum key and presents it on every call.

Routes:

- `GET /health`: `{"status":"Healthy"}` once runtime keys are loaded.
- `GET /v1/info`: untrusted discovery the client binds to a signed release policy.
- `POST /v1/ping`: QOS connection challenge.
- `POST /v1/operations`: `Bootstrap`, `Decrypt`, `Derive`, `TransactionKeys`,
  `Prove`, specified in [`crates/protocol`](../../crates/protocol/README.md).

Module map: `operations/` (request validation, `bootstrap.rs`, `keys.rs` for
the three derivation operations, `prove.rs` for completing a prover request
and sealing it to an attested prover, `sealed.rs` for the sealed seed),
`custody.rs` (Turnkey signing of the derivation message behind one trait),
`turnkey.rs` (Turnkey API stamping with the Quorum signing subkey),
`local_dev.rs` and `local_prover.rs` (testkit, `local-dev` feature only).

The only network origin is Turnkey, compiled in. A proof's witness is sealed to
a prover the network's signed prover policy admits and posted by the client.
The network is fixed at build time by `SPR_NETWORK` (`devnet`, the default for
local builds, or `mainnet`); the image pins that network's policy signers.

## Build

```sh
just check lint test                 # from the repository root
just image-privacy-wallet mainnet    # linux/amd64 image; prints the /tvc_app SHA-256
```

## Local testkit

Unattested. Real handlers, pinned local QOS keys instead of Nitro, a local
Ed25519 key instead of Turnkey, and a stand-in attested prover on
`--prover-tee-port` (default 44021). The stand-in signs Nitro documents under a
fixture root the local enclave trusts, publishes a two-part policy file whose
release the testkit's policy signer signs at `/local/prover-policy`, opens sealed requests and
forwards them to the plaintext prover at `--prover-url`. `just headless-e2e`
runs it end to end; to run it by hand:

```sh
cargo run -p zolana-tvc-privacy-wallet --features local-dev \
  --bin zolana-tvc-privacy-wallet-local -- \
  --wallet-keypair /path/to/disposable-keypair.json --prover-url http://127.0.0.1:3001
```

Clients prove through `http://127.0.0.1:44021` (`localProverConfig` in
`@heliuslabs/spr-embedded-wallet/testing`).

`--live-prover` starts no stand-in: the local enclave seals witnesses only to a
prover whose Nitro attestation chains to the production AWS root and passes
the network's signed policy, as the enclave image does. Clients prove through
that network's TEE provers with `TvcProverPolicy.forNetwork(network)`; the
custody and QOS keys stay local and unattested.

The `local-dev` feature is never enabled in the enclave binary.
