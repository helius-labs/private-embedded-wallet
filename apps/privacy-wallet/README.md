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
- `POST /v1/decryption-service`: the [decryption service](#decryption-service-prototype).

Module map: `operations/` (request validation, `bootstrap.rs`, `keys.rs` for
the three derivation operations, `prove.rs` for completing a prover request
and sealing it to an attested prover, `sealed.rs` for the sealed seed),
`network.rs` (what the image trusts on each network), `custody.rs` (Turnkey
signing of the derivation message behind one trait),
`turnkey.rs` (Turnkey API stamping with the Quorum signing subkey),
`local_dev.rs` and `local_prover.rs` (testkit, `local-dev` feature only).

The only network origin is Turnkey, compiled in. A proof's witness is sealed to
a prover the network's signed prover policy admits and posted by the client.
The network is fixed at build time by `SPR_NETWORK` (`devnet`, the default for
local builds, or `mainnet`), which picks one entry of `network.rs`: the
network `/v1/info` names and descriptors must name, the provisioning and
wallet-grant public keys of that network's tvc-gateway, and the network's
prover policy signers.

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

Clients prove through `http://127.0.0.1:44021` (`createLocalTvcClient`'s
`prover: localProverConfig(url)` in `@heliuslabs/spr-embedded-wallet/testing`).

`--live-prover` starts no stand-in: the local enclave seals witnesses only to a
prover whose Nitro attestation chains to the production AWS root and passes
the network's signed policy, as the enclave image does. Clients of that network
(`createLocalTvcClient({ network, prover: { url } })`) prove through its TEE
provers under its policy; the custody and QOS keys stay local and unattested.

The `local-dev` feature is never enabled in the enclave binary.

## Decryption service (prototype)

Lets a Solana address receive private transfers before its owner registers a
wallet. The enclave derives one viewing key and one nullifier key per address,
its service keys, from a master seed sealed to the Quorum key. The requests,
results and signed messages are specified in
[`crates/protocol`](../../crates/protocol/README.md#decryption-service).

1. An operator runs `Genesis` once and publishes the sealed master seed. Every
   later request presents it.
2. A sender calls `PublicKeys` for an address and encrypts a transfer to the
   keys it returns.
3. The owner signs, with the address, a message that names the batch of
   outputs and a viewing key of the owner's own wallet, and calls `Decrypt`.
   The enclave opens every output with the service viewing key and returns
   the plaintexts and the service nullifier secret, encrypted to the named
   key. The client keeps a plaintext only when its commitment equals the
   indexed one.

`Claim` is the other design, kept to compare the two: after a signature that
names only the wallet viewing key, it returns both service secrets, and the
wallet opens later transfers itself.

The code is `src/decryption_service/`: `mod.rs` (the four operations),
`keys.rs` (the derivation), `seed.rs` (the master seed, encrypted to the
Quorum key and signed by it), `owner.rs` (which addresses have keys, the
owner's signature, sealing an answer). It opens the request envelope, opens
ciphertexts and builds the proof-carrying response with the wallet
operations' own functions. It reads no wallet descriptor or grant and reaches
no service.

The local testkit serves the route. Nothing calls it yet but its tests, which
decrypt an output encrypted as a sender encrypts it:

```sh
cargo test -p zolana-tvc-privacy-wallet --all-features decryption_service
```

Not there yet:

- `/v1/info` and the release policy do not name its operations.
- No wallet operation opens a sealed answer, so a wallet whose viewing key
  lives in this enclave cannot read one.
- No gateway route and no client.
- The master seed has no copy outside the Quorum key, and no release step
  pins the result of `Genesis`.
- `Decrypt` and `Claim` are both served; one of them is to go.

## Release

`deploy/release.json` holds the release constants, shared at the top and per
network under `networks`; `deploy/<network>/` holds that network's Turnkey app
and deployment files. `just release <network> <release-id> --image <reference>`
deploys the network's image and pins its signed release in
`packages/tvc-wallet/src/releases/<network>.json`; see
[`scripts/README.md`](../../scripts/README.md#release).
