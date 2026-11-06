# `@heliuslabs/spr-embedded-wallet`

Client for the TVC privacy wallet of Solana Privacy Rings. It verifies the
signed release policy and the AWS Nitro Boot Proof of the enclave before its
first request, wraps every operation in a QOS P-256 envelope, checks the
proof-bound result, and answers the Zolana SDK's `WalletKeys` interface, so
every `@heliuslabs/spr` flow runs over the enclave unchanged.

Pre-production. Requires `@heliuslabs/spr` 0.9.0-alpha or later, which
speaks the `/v1/spr` prover contract and reads the signed prover policy file
the enclave checks.

## Usage

```ts
import { Wallet, createSprClient, syncWallet } from "@heliuslabs/spr";
import { createTvcClient } from "@heliuslabs/spr-embedded-wallet";

// 1. The app logs the user in with Turnkey; `turnkey` is @turnkey/core's client, or useTurnkey().
const endpoint = new URL(`https://devnet.helius-rpc.com/v1/private-wallet?api-key=${apiKey}`);
const tvc = createTvcClient({ network: "devnet", endpoint, turnkey });

// 2. The wallet's keys: reopened from the last `keys.stored`, or bootstrapped once with the owner's approval.
const keys = await tvc.open(stored, { approve });
await save(keys.stored);

// 3. The SDK, with the enclave's keys in place of `LocalKeys`.
const zolana = await createSprClient({ solanaRpcUrl, indexerUrl, proverUrl, proverTee, proofDataSource: "client" });
const wallet = new Wallet({ identity: keys.address() });
await syncWallet({ client: zolana, wallet, keys });
```

`createTvcClient({ network, endpoint, turnkey, solanaAddress?, prover?, nowMs?, transport?, requestTimeoutMs? })`:

- `endpoint` is the network's tvc-gateway, Helius's
  `https://<network>.helius-rpc.com/v1/private-wallet?api-key=…` or an
  application's proxy of it. Its query travels on every route.
- `turnkey` is the application's Turnkey client with a logged-in session:
  `@turnkey/core`'s `TurnkeyClient`, or what `useTurnkey()` returns in
  `@turnkey/react-wallet-kit`, as it is. The client uses four of its methods,
  typed as `TvcTurnkey`: `getSession`, `signWithApiKey`, `fetchWallets` and
  `signMessage`. A server implements them over a Turnkey API key; see
  [the example](../../examples/typescript-client/src/lib.ts).
- `solanaAddress` names the wallet when the session's organization holds more
  than one embedded Solana account; by default the client takes the only one.
- `prover` is the attested prover the enclave seals proofs to and the client
  posts them to. It defaults to `/v1/spr` on the endpoint's origin with the
  endpoint's query, where Helius serves the network's TEE prover.
- `transport` carries every HTTP request the client makes: the gateway, the
  prover and the prover's policy file.

`tvc.open(stored?, { approve?, signal?, timeoutMs? })` returns `TvcKeys`, the
SDK's `WalletKeys`, with `keys.stored` to persist. Neither part of it is a
secret to the client:

- `stored` with its `sealedSeed` reopens the wallet without a call, under
  any session key of the wallet: a new login needs no bootstrap.
  `parseStoredWallet` reads a stored value back and refuses anything else.
- Without `stored`, the enclave bootstraps the wallet: it derives the
  shielded identity from a Turnkey signature over a fixed message and returns
  the seed sealed to the release's Quorum key. A wallet whose Turnkey policy
  requires the owner to co-sign that signature passes `approve(bootstrap,
  signal)`, which runs `bootstrap` and approves the activity it starts; see
  [the example](../../examples/typescript-client/src/bootstrap-approval.ts).
  `approve` runs only after the enclave verified.
- `{ identity }` without a sealed seed bootstraps again and refuses any other
  identity (`ShieldedIdentityChanged`): the recovery path after the sealed
  seed is lost or a Quorum key rotation retired it. The seed is a
  deterministic signature, so the identity does not change.

`tvc.servicePublicKey` is the Turnkey API key the enclave signs the bootstrap
message with (the compressed signing half of the release's Quorum key), which
the wallet's bootstrap policy names.

## Verification

The client verifies the enclave on its first call, not when it is created:
the signed release policy, the policy's binding of discovery (`/v1/info`), the
Quorum-encrypted ping, and the Boot Proof of the replica that answered.
Concurrent first calls share one verification. Every operation then checks
the policy's validity window before it signs and again on the answer, and
verifies the Boot Proof of whichever replica answered it. The client verifies
again before the next call when the policy's window no longer holds, and after
the backend refuses or fails an operation (any HTTP error but a 429): a new
deployment or a rotated Quorum key epoch refuses requests bound to the old
discovery. It does not repeat the failed operation. It also verifies again
when the Turnkey session key changes.

The enclave's five operations, specified in
[`crates/protocol`](../../crates/protocol/README.md), stay behind `TvcKeys`
and `open`. No operation returns a long-lived secret, none signs a Solana
transaction, and none takes a caller-selected network origin.

## Networks

`network`, `devnet` or `mainnet`, is the network the enclave serves, and the
client is for that network only:

- The release it verifies the enclave against is this package's
  `src/releases/<network>.json`, which `scripts/release.mjs` writes and
  tvc-gateway reads. `createTvcClient` throws `ReleaseNotPinned` for a network
  without one; mainnet has none yet. `createTestTvcClient` in `./testing`
  takes another release for a test deployment.
- The signed policy names its network, and verification refuses a policy, or
  a `/v1/info`, for another (`NetworkMismatch`). Operations refuse a wallet
  descriptor for another network before they sign.
- Proofs go under the network's signed prover policy file.
- `walletEnrollmentMessage` signs for the gateway's network as its chain.

`TvcKeys` is the same surface as the SDK's `WalletKeys`. It splits the items
of one SDK call into batches of at most 256, splits further when the full
serialized HTTP envelope exceeds the advertised request byte limit, and forwards the SDK's
`RequestContext` (abort signal and timeout) to every batch, so a cancelled
sync stops its decrypt batches as a cancelled build stops its proof. The pool
cipher is unauthenticated, so the SDK adopts a decrypted UTXO only when its
commitment matches the indexed output.

A proof is at most three calls after the policy file. The client downloads
the network's signed policy file and holds it for its `max_age_secs`, for
every wallet it opens; the enclave, not the client, checks its signatures and
versions. Concurrent callers share one download, and each can abandon its own
wait. `TvcKeys`
fetches the prover's attestation for a fresh nonce (`GET <url>/attestation`)
and reuses it for the same `max_age_secs`, asks the enclave to complete the
request and seal it to the attested key under that file, and posts the sealed
request to `<url path>/prove/<key>` with the URL's query, such as its API key.
It opens the answer with the response key the enclave returned, which opens
nothing else. When the enclave refuses the policy or attestation (a
`TvcOperationError` with `stage: "Prover"`), or the prover answers
`tee_decryption_failed`, the client downloads the policy again, attests again
and seals once more. Neither the client nor any proxy in front of
the prover holds the witness in plaintext.

The enclave binds a sealed request to its route below the prover's URL,
`/prove/<key>`, so a gateway or proxy may serve the prover on any path. It must
forward the request with its `Spr-Tee` headers and body unchanged.

Prover failures, including encrypted failures, retain their status and
`Retry-After` as `TvcHttpError`. They are returned without automatically
repeating the proof; only the explicit key-loss response triggers the bounded
reattestation flow. Configure the proxy to disable unsafe-method retries
(`disableUnsafeRetries: true` in Gatekeeper). A 5xx can follow execution and
does not establish that the proof or a signed operation never ran.

`snapshotCipher(keys, context?)` is the SDK's `WalletStateCipher` for
`syncPersistedWallet` and `loadPersistedWallet`. Its key is a per-transaction
key the enclave mints under a context no transaction can have, so a sealed
wallet snapshot persists at rest and reopens on any device that can drive this
wallet's enclave operations.

`open` takes `{ signal, timeoutMs }`, and `TvcKeys` forwards the SDK's
`RequestContext`. Each bounds the verification and the operation, each
defaulting to two minutes, including request signing, reading the response,
and Boot Proof lookup. Set `requestTimeoutMs` in the client configuration to
change that default. Concurrent callers share one verification; cancelling one
does not cancel another. When all callers leave, the verification stops and a
late response cannot replace a newer one.

Snapshot loading accepts the SDK's `RequestContext` and destroys temporary key
material on success, failure, or cancellation. HTTP failures are `TvcHttpError`
instances with `status` and the raw `retryAfter` header. An operation that ran and
failed at a named stage is a `TvcOperationError` with its `operation` and `stage`
(`Prover`, or `TurnkeySigning` when Turnkey declined the bootstrap signature).
The client does not retry a failed operation automatically.

## The session key

The client key is the Turnkey session key. Turnkey's client holds a
non-exportable P-256 key for each login session. The client signs every
request with it through `signWithApiKey`, over the client-auth text
`spr-tvc-client-auth-v1:<request digest, lowercase hex>` (ECDSA P-256 over
SHA-256), normalizes the signature to low S, and checks it against the key
before it sends.

On first use the client enrolls the key with the gateway. It finds the
wallet's Solana account (`fetchWallets`; connected wallets are skipped), has
the wallet sign `walletEnrollmentMessage` with Ed25519 (`signMessage`, a text
payload, unhashed), a Sign-In With Solana message for the endpoint's host
whose chain is the network, and posts
`{organizationId, turnkeyWalletId, solanaAddress, clientPublicKey, issuedAtMs, ownerSignature}`
to `<endpoint>/enroll`. The gateway answers a descriptor for the key, which
the client checks and keeps in memory for that key. A new login, or
`refreshSession` without the current public key, brings a new session key:
the client enrolls it before the next request and verifies the enclave again.
The sealed seed is bound to the wallet (network, security domain, Turnkey
organization and wallet, address), not to the key, so a stored wallet opens
under every session key of its owner.

Errors: `TurnkeySessionRequired` without a logged-in session,
`WalletAccountNotFound` or `WalletAccountAmbiguous` when the account cannot be
told, and `EnrollmentRejected` with the gateway's status. The wallet's Turnkey
sub-organization must be named after the API key's Helius project. See
[`apps/tvc-gateway`](../../apps/tvc-gateway/README.md#enrollment).

## Entry points

- `@heliuslabs/spr-embedded-wallet`: `createTvcClient`, `TvcTurnkey`,
  `TvcKeys`, `parseStoredWallet` and `snapshotCipher`.
- `@heliuslabs/spr-embedded-wallet/protocol`: wire types, `TvcError`, hex codecs,
  `clientKeyIdFor`, and `walletEnrollmentMessage`, the Sign-In With Solana
  message the wallet signs to enroll a key with tvc-gateway.
- `@heliuslabs/spr-embedded-wallet/testing`: `createTestTvcClient`, which
  verifies an enclave as `createTvcClient` does against a release and backend
  the caller names (a gateway, or the enclave itself with
  `{ kind: "enclave", endpoint, resolveBootProof, walletGrant }`), with the
  Turnkey session or a descriptor and the signer of its key
  (`createTvcRequestSigner`), and `createLocalTvcClient`, the loopback-only
  unattested testkit client for the network the testkit was built for. The
  build fails if testkit code becomes reachable from a production entry.

## Verification

From the repository root:

```sh
pnpm ci:ts
```
