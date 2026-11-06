# TypeScript client with a TVC wallet

A client example for `@heliuslabs/spr` with the shielded keys held by a TVC
enclave (`@heliuslabs/spr-embedded-wallet`), in the layout of
[zolana-examples](https://github.com/helius-labs/zolana-examples).

- **[deposit_transfer_withdraw](examples/deposit_transfer_withdraw.ts)** - Deposit, private transfer, and withdraw, with the enclave as the key holder
- **[spl_deposit_transfer_withdraw](examples/spl_deposit_transfer_withdraw.ts)** - The same lifecycle for an SPL token registered with the pool
- **[merge](examples/merge.ts)** - Merge the wallet's SOL notes into one

## What a TVC wallet is

In the plain client, the application holds the shielded keys of a private
wallet. In a TVC wallet, an attested enclave (Turnkey Verifiable Compute on
AWS Nitro) holds them and answers the SDK's `WalletKeys` with them. The
application still runs the Zolana SDK for everything else, and every Solana
transaction is signed by the Turnkey wallet that owns the identity: in a
browser by the signed-in session, here by a Turnkey API key. This is for
applications with Turnkey embedded wallets that want private balances without
keeping shielded keys in a browser or on a server. The
[repository README](../../README.md) describes the split and the five enclave
operations.

## How the example works

1. `setup()` reaches the enclave of the network `SPR_NETWORK` names through
   that network's Helius-hosted tvc-gateway, verifies it against the release
   the package pins for the network, and returns the client, verified
   connection, and wallet signer.
2. `bootstrap` runs once per wallet. Its result, the public identity and the
   sealed seed, is stored in a file. Neither is a secret to the client. If the
   file is lost, `bootstrap` runs again and returns the same identity. Both
   initial setup and recovery first configure the Turnkey grant, then
   automatically approve the exact bootstrap request through the configured
   owner session, within the same `bootstrap()` call.
3. `new TvcKeys({ client, connection, sealedSeed, identity, prover })` is the
   SDK's `WalletKeys`, answered by the enclave; it proves under the network's
   signed prover policy.
4. The SDK does the rest: `Wallet`, `syncWallet`, `buildDepositTransaction`,
   `buildTransferTransaction`, `buildWithdrawalTransaction`. The calls are the
   same as with local keys.
5. The application signs each transaction with the Turnkey wallet, sends it,
   confirms it and syncs the wallet to the landed slot.

The plain client does the same with `LocalKeys.fromKeypair(keypair,
client.proofService)` in place of `TvcKeys`. Nothing else changes.

## What you need

- Node.js 24+, pnpm, and a Helius API key (`API_KEY`). The network's
  Helius host, `devnet.helius-rpc.com` or `mainnet.helius-rpc.com`, serves
  everything else: the RPC, the indexer and the TEE prover at `/v1/spr`, and
  the network's private-wallet gateway at `/v1/private-wallet`.
- A Turnkey sub-organization named after the API key's Helius project, with a
  Solana wallet, and a root user's API key in it, as the key pair or a Turnkey
  API key file (`TURNKEY_API_KEY_PATH`). Helius creates these sub-organizations
  for an embedded-wallet project; the gateway refuses a wallet in any other
  (`SubOrganizationNotOwned`). The example signs with the key, enrolls with
  it, and configures the enclave's grant with it before a bootstrap. A browser
  integration uses the authenticated owner session instead; never embed a root
  API key in browser code.

The first run enrolls the client key: the wallet owner signs a Sign-In With
Solana message for the gateway's host and network, and
`POST /v1/private-wallet/enroll` answers a wallet descriptor for that network,
stored at `TVC_DESCRIPTOR_PATH`. The client verifies the enclave against the
package's release for the network, `RELEASES[network]`; a network without one
(mainnet until its first release) fails with `ReleaseNotPinned`. A stored
descriptor for another network is refused; keep one descriptor file per
network.

## Setup

From the repository root:

```bash
pnpm install
pnpm build:ts
cd examples/typescript-client
cp client.env.example .env # ...and fill in the values
```

## Run

With the wallet configuration in `.env`, run one command. No separate
enrollment or approval command is needed:

```bash
pnpm example examples/deposit_transfer_withdraw.ts
```

The examples check balance changes relative to the wallet's starting balance,
so they can be rerun with an existing wallet.

The Turnkey wallet pays fees and the deposit, so it needs devnet
SOL: the SOL example deposits 0.01 SOL, so 0.1 SOL covers a run of
everything. For the SPL example set `SPL_MINT`, `SPL_ASSET_ID` (the id the pool
registered the mint under) and `SPL_TOKEN_ACCOUNT` (the wallet's token account
the deposit leaves from), and optionally `SPL_AMOUNT`:

```bash
pnpm example examples/spl_deposit_transfer_withdraw.ts
```

The merge example consolidates the wallet's SOL notes into one. It sets the
registry record's merge encryption to `PoseidonCtrV1` if it is not set yet,
which lets anyone merge the owner's notes, deposits 0.005 SOL until the wallet
holds at least two notes, and merges up to 24 of the smallest. The enclave
answers the merge derivations, including the output ciphertext key, and seals
the merge proof:

```bash
pnpm example examples/merge.ts
```

## Bootstrap authorization

The client returned by `setup()` keeps the normal `tvc.bootstrap(connection)`
interface. While that call is active, it finds a new pending Turnkey activity,
checks the exact SDK derivation message, wallet, organization, pinned service
signing key, and freshness, then approves the checked fingerprint using the
owner session. Previous pending activities and unrelated messages are skipped;
multiple matching activities fail rather than choosing one arbitrarily. The
watcher stops when bootstrap finishes, fails, is cancelled, or reaches its
65-second deadline. The enclave briefly retries permission denials while new
grants propagate, then polls the original activity. Run one bootstrap per
wallet at a time. Stored wallets
reuse their sealed seed and need no further approval polling.

The policy still requires **both** the owner and the service user. Automation
runs in the owner client; it does not give the service the owner's credential.
Turnkey [policy parameters](https://docs.turnkey.com/features/policies/language#activity-parameters)
cannot inspect the payload, so that exact-message check remains essential.
Before each bootstrap the example sets its policy to name the enclave's current
service user, the client's `servicePublicKey` from the network's release, so a
Quorum key rotation needs no manual step. Separately created
signing grants must be reviewed by the operator.

The owner approval API can return the bootstrap signature. The adapter discards
the result and does not log it; it must run in a trusted owner environment.
This restriction does not protect privacy secrets after a quorum-key compromise
or undo previous exposure.

On 2026-11-05, against release `private-wallet-devnet-31a9dec`, the SOL
example and the merge example ran through the hosted gateway, with the indexer
and the prover at gatekeeper's `/v1/spr`: enrollment, verification, bootstrap
with automatic owner approval, deposit, private transfer, withdrawal and a
two-note merge all finalized on devnet.

## Run locally

The examples run against the local testkit and a fresh Zolana localnet, with
a disposable keypair as the wallet in place of Turnkey and pinned process keys
in place of Nitro attestation. The Rust testkit runs the real handlers of the
five operations; the `@heliuslabs/spr-embedded-wallet/testing` client still verifies
envelopes, signatures and bindings, and accepts loopback HTTP only. It needs a
sibling `../zolana` checkout at the commit
[`headless-local-e2e.yml`](../../.github/workflows/headless-local-e2e.yml)
pins, with its localnet toolchain (Solana CLI, Go, Rust, `just`). From the
repository root:

```bash
just headless-e2e        # port offset 200
just headless-e2e 400
```

The recipe builds the package, starts the validator, Photon and the prover
(`scripts/start-localnet.sh`, which also mints a test SPL asset), starts the
testkit, funds the keypair, runs the two examples,
and tears everything down. The same workflow runs it in CI. Setting
`TVC_LOCAL_TESTKIT_ENDPOINT` (with
`TVC_SOLANA_KEYPAIR_PATH`, `TVC_WALLET_PATH`, the `ZOLANA_*` URLs and the
`SPL_*` values) runs an example against a stack you started yourself.

The testkit also runs against a live network. Started with `--live-prover`, it
seals witnesses to the network's TEE provers under its signed policy rather
than to its stand-in. Set `TVC_PROVER_URL` to one of them and `API_KEY`, and
leave the `ZOLANA_*` URLs unset for the network's RPC, indexer and prover. The
testkit serves the network it was built for, so a mainnet testkit needs
`SPR_NETWORK=mainnet` both when it is built and when the example runs:

```bash
cargo run -p zolana-tvc-privacy-wallet --features local-dev \
  --bin zolana-tvc-privacy-wallet-local -- \
  --wallet-keypair /path/to/disposable-keypair.json --live-prover
```

## Persistence

The example syncs the wallet from the index on every run. An application that
reopens a wallet often can store the SDK wallet snapshot instead. The enclave
provides the snapshot key, so no secret is kept on the device:

```ts
import { loadPersistedWallet, syncPersistedWallet } from "@heliuslabs/spr";
import { snapshotCipher } from "@heliuslabs/spr-embedded-wallet";

const cipher = await snapshotCipher(keys);
const wallet =
  (await loadPersistedWallet({ store, cipher })) ?? new Wallet({ identity });
await syncPersistedWallet({ client, wallet, keys, store, cipher });
```

`store` is any `{ load, save }` pair over a string, for example a file or
IndexedDB.

## Notes

- Pre-production, disposable funds. `SPR_NETWORK` (`devnet` by default, or
  `mainnet`) is the client's network: it picks the Helius host, the gateway
  and the enrollment domain on it, the pinned release, the enrollment chain,
  and the prover policy. The enclave seals each proof's witness to the
  attested prover at `TVC_PROVER_URL` (default gatekeeper's `/v1/spr`); the
  client-side prover at `ZOLANA_PROVER_URL` never sees an enclave witness. `ZOLANA_ENDPOINT`, `ZOLANA_INDEXER_URL`,
  `ZOLANA_PROVER_URL` and `TVC_GATEWAY_URL` override the Helius routes.
- Never commit `.env`, the client key, the descriptor, or the stored wallet.

## Documentation

- [Connect](https://www.helius.dev/docs/privacy/connect)
- [Documentation](https://helius.dev/docs/privacy)
- [Source Code](https://github.com/helius-labs/zolana)
- [`@heliuslabs/spr-embedded-wallet`](../../packages/tvc-wallet/README.md)
