# Zolana TVC privacy wallet

A Zolana shielded wallet whose privacy keys live in a Turnkey Verifiable
Compute enclave. The enclave holds the nullifier and viewing keys and answers
the Zolana SDK's `WalletKeys` interface with them: it opens ciphertexts, derives
nullifiers, mints per-transaction keys, and completes proof witnesses. The
client runs every wallet flow with the Zolana TypeScript SDK, `TvcKeys` in
place of `LocalKeys`: sync, selection, transfers, withdrawals, splits, merges,
rings, deposits, registration, signing, and submission.

Pre-production, for disposable devnet funds. The witness, which holds the
long-lived nullifier secret, reaches only an attested TEE prover; see
[Network boundary](#network-boundary).

Helius hosts it on devnet behind gatekeeper: the private wallet at
`https://devnet.helius-rpc.com/v1/private-wallet` (also on `beta-devnet`), and
the Zolana indexer and TEE prover at `/v1/spr` on the same host, all with a
Helius API key.

| Path | Purpose |
| --- | --- |
| [`apps/privacy-wallet`](apps/privacy-wallet) | The TVC application and an unattested local testkit. |
| [`apps/tvc-gateway`](apps/tvc-gateway) | The Helius-hosted backend at `/v1/private-wallet`: one-request sessions with Boot Proofs, enrollment, and wallet grants. |
| [`packages/tvc-wallet`](packages/tvc-wallet) | TypeScript client: connection verification, the five operations, `TvcKeys` for the Zolana SDK, browser persistence. |
| [`crates/protocol`](crates/protocol) | The protocol specification and its Rust implementation: wire types, JCS, digests, client authorization, QOS envelope, release policies, conformance fixtures. |
| [`examples/typescript-client`](examples/typescript-client) | Enrollment, then SOL and SPL lifecycles and a merge, through the hosted gateway or against the local testkit. |
| [`scripts`](scripts) | Operator tooling: per-network releases, service keys, the localnet for `just headless-e2e`. |

## Responsibility split

```mermaid
flowchart LR
    C[Client + Zolana SDK]
    T[TVC enclave]
    K[Turnkey]
    I[Indexer]
    P[Prover]
    S[Solana RPC]

    C -->|decrypt, derive, transaction keys, prove| T
    C <-->|outputs by tag, spent nullifiers, Merkle proofs| I
    C -->|asset registry, blockhash| S
    C -->|attestation; sealed witness| P
    T -->|bootstrap signature request| K
    C -->|owner approves exact bootstrap message| K
    C -->|signed transaction| S
```

The enclave serves five operations at `POST /v1/operations`:

| Operation | Answers |
| --- | --- |
| `Bootstrap` | The wallet's public identity and its seed, sealed to the enclave's Quorum key. Turnkey signs a fixed message after owner approval; the deterministic signature is the seed, expanded into the keys inside the enclave. Once per wallet, and again for recovery. |
| `Decrypt` | The plaintext of the encrypted outputs the client fetched from the index, in batches; the client matches commitments and keeps the Zolana `Wallet`. |
| `Derive` | The nullifiers and merge blindings of a spend. |
| `TransactionKeys` | The per-transaction viewing key that encrypts a spend's outputs, minted for the spend's first nullifier. |
| `Prove` | The witness sealed to an attested prover. The SDK assembles it with the nullifier-secret slots open; the enclave fills them, checks the prover's attestation against the network's signed prover policy, and encrypts the witness to that prover's key. The client posts it and opens the proof. |

They are exactly the Zolana SDK's `ShieldedKeys` and `ProofAuthority` methods,
so `TvcKeys` implements the SDK's `WalletKeys` and every SDK flow runs
unchanged over the enclave. Everything else is the client's: registration and
deposits with the ordinary Turnkey wallet, input selection, output encryption,
and signing and submitting every Solana transaction with the application's
own signer. The enclave never sees a balance, never selects an input, and
never signs a Solana transaction. Request and response semantics, the
envelope, digests, descriptors, sealed seeds, and release policies are
specified in [`crates/protocol`](crates/protocol/README.md).

## Trust

Trust material arrives out of band: a threshold-signed release policy, the
authority public keys, and PCR pins, one release per network
(`packages/tvc-wallet/src/releases/<network>.json`). The policy names its
network, `devnet` or `mainnet`, and a client accepts it only for the network
it was created for. `connectAndVerify()` verifies the policy,
binds `GET /v1/info` to it, completes the Quorum-encrypted `POST /v1/ping`,
and verifies the Nitro Boot Proof against the PCRs and accepted manifest
digests. Wallet calls take the resulting `VerifiedConnection` only; HTTPS
alone establishes nothing. A wallet descriptor, signed by the operator with the
provisioning key whose public half is compiled into the image, grants a client
key the operations of one Turnkey wallet. Each operation also carries a wallet
grant, signed with the grant key, that is at most an hour old; a client key
whose grants stop being issued stops within the hour.

## Network boundary

Callers never name an origin. Every destination is compiled into the measured
executable, so changing one is a new release.

| Destination | Used for |
| --- | --- |
| `api.turnkey.com` | Bootstrap signing |

A proof's witness leaves the enclave only sealed to a TEE prover whose
attestation passes the signed prover policy of the network the image was built
for (`SPR_NETWORK`, `devnet` or `mainnet`). The client downloads the policy
file that network publishes and hands it to the enclave, which checks it
against the signers zolana pins for that network
([`network.rs`](apps/privacy-wallet/src/network.rs)); the client posts the
sealed request, and only that prover can open it. A new prover release needs
no new enclave release; a change of signers does.

Enrollment requires an independent owner approval of the exact bootstrap
message; the service credential alone must not authorize wallet signatures.
See the [automatic client approval](examples/typescript-client/README.md#bootstrap-authorization).
This limits signing authority, not the damage to privacy secrets after a
quorum-key compromise: Turnkey can reproduce the bootstrap seed, and the
network's policy signers decide which prover images may read a witness.
Production needs an external egress boundary enforcing this table and release
governance with rotation and revocation for the release keys.

## Development

Rust from `rust-toolchain.toml`, Node 24, pnpm 9, `just`, Docker with
`linux/amd64`:

```sh
just setup
just ci
```

`just ci` runs fmt, clippy, the Rust tests, the committed-fixture check, and
the TypeScript lint, typecheck, tests, and build. `just headless-e2e` runs the
client example's SOL and SPL lifecycles against the testkit and
a local Zolana network built from a sibling `../zolana` checkout, which must be
at the commit
[`headless-local-e2e.yml`](.github/workflows/headless-local-e2e.yml) pins.

Never commit Turnkey operator files, API keys, or `.env.local`.

## Deployment

Each network, `devnet` or `mainnet`, has its own Turnkey TVC app, Quorum key,
operators, `linux/amd64` image built for it and pinned by `@sha256:`, signed
release policy, tvc-gateway, and wallet descriptors. The constants are in
[`apps/privacy-wallet/deploy/release.json`](apps/privacy-wallet/deploy/release.json),
shared at the top and per network under `networks`, and each network's
deployment files in `apps/privacy-wallet/deploy/<network>/`. A release of one
network is one command:

```sh
just release devnet private-wallet-devnet-<sha> --image <reference>
```

It pins the signed release in `packages/tvc-wallet/src/releases/<network>.json`,
which the client exports and tvc-gateway reads. Wallet descriptors come from
the network's tvc-gateway, which signs one on each
`POST /v1/private-wallet/enroll`. [`scripts/README.md`](scripts/README.md)
describes the release phases and the localnet.

## License

Protocol, client, and verifier code is Apache-2.0. The TVC application links
AGPL QOS crates and is AGPL-3.0-only; see the individual manifests. The
protocol crate's tests link `qos_p256` (AGPL-3.0-only) to prove envelope
compatibility; it is not a runtime dependency.
