# `@heliuslabs/spr-embedded-wallet`

Private balances for Turnkey embedded wallets on Solana Privacy Rings. The
wallet's privacy keys live in an attested enclave (Turnkey Verifiable
Compute), not in the browser. This client verifies the enclave's signed
release policy and AWS Nitro Boot Proof before its first request, encrypts
every operation to the enclave, checks each answer, and implements the SDK's
`WalletKeys` over it, so every `@heliuslabs/spr` flow runs unchanged.

Pre-production. ESM only. Needs `@heliuslabs/spr` 0.9 (`^0.9.0-alpha`) and
`@solana/kit` 8 as peers, and Node 24 or a browser bundler.

## Integration guide

This guide is for an application already on Helius wallet-kit
(`helius-wallet-kit`) with WaaS enabled on its Helius project. Its users'
Turnkey wallets are the private wallets' owners.

### 1. Install

```sh
npm install @heliuslabs/spr-embedded-wallet @heliuslabs/spr @solana/kit
```

### 2. Forward two Helius routes

The browser must not hold the Helius API key. One server route forwards
`/v1/private-wallet/*` (the private wallet) and `/v1/spr/*` (the indexer and
the TEE prover) to `https://<network>.helius-rpc.com` and adds the key.
`helius-wallet-kit/next` will ship this route. Until then, its shape in the
Next.js App Router:

```ts
// app/api/helius/v1/[...path]/route.ts
const UPSTREAM = "https://devnet.helius-rpc.com";
// The headers the client, the SDK and the TEE prover use, each way.
const REQUEST_HEADERS = ["accept", "content-type", "spr-tee", "spr-tee-enc", "spr-tee-ciphertext", "x-sync", "x-async"];
const RESPONSE_HEADERS = ["content-type", "retry-after", "spr-tee"];

async function forward(request: Request, { params }: { params: Promise<{ path: string[] }> }) {
  // Other sites must not spend the project's credits through this route.
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return new Response(null, { status: 403 });
  const { path } = await params;
  const url = new URL(`/v1/${path.join("/")}`, UPSTREAM);
  if (!/^\/v1\/(private-wallet|spr)(\/|$)/.test(url.pathname)) return new Response(null, { status: 404 });
  url.search = new URL(request.url).search;
  url.searchParams.set("api-key", process.env.HELIUS_API_KEY!);
  const headers = new Headers();
  for (const name of REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  const answer = await fetch(url, {
    method: request.method,
    headers,
    body: request.method === "POST" ? await request.arrayBuffer() : undefined,
    redirect: "error",
    cache: "no-store",
  });
  const answerHeaders = new Headers({ "cache-control": "no-store" });
  for (const name of RESPONSE_HEADERS) {
    const value = answer.headers.get(name);
    if (value !== null) answerHeaders.set(name, value);
  }
  return new Response(answer.body, { status: answer.status, headers: answerHeaders });
}

export { forward as GET, forward as POST };
```

Forward bodies unchanged and never retry a POST: a repeated operation can
run twice. Next.js serves this route next to wallet-kit's
`app/api/helius/[...path]` catch-all.

### 3. Create the client

```ts
import { useTurnkey } from "@turnkey/react-wallet-kit";
import { createSprEmbeddedWallet } from "@heliuslabs/spr-embedded-wallet";

const turnkey = useTurnkey(); // inside HeliusWalletProvider
const tvc = createSprEmbeddedWallet({
  network: "devnet",
  endpoint: new URL("/api/helius/v1/private-wallet", location.origin),
  prover: new URL("/api/helius/v1/spr", location.origin),
  turnkey,
});
```

`useTurnkey()`'s methods use the Turnkey client of the render they come
from. Create the TVC client once `turnkey.clientState` is
`ClientState.Ready`, and keep it for the page's life: a new client verifies
the enclave again. `prover` is needed because the route is not at `/v1/spr`
on the page's origin.

### 4. Open the wallet

```ts
import { parseStoredWallet } from "@heliuslabs/spr-embedded-wallet";

const saved = localStorage.getItem(storageKey);
const stored = saved === null ? undefined : parseStoredWallet(JSON.parse(saved));
const keys = await tvc.open(stored, { approve });
localStorage.setItem(storageKey, JSON.stringify(keys.stored));
```

Without `stored`, the enclave bootstraps the wallet. With its Turnkey API
key, `tvc.servicePublicKey`, it asks Turnkey to sign a fixed message with the
user's wallet, and the owner must approve that signature too.
`approve(bootstrap, signal)` is the owner's part. It makes sure the wallet's
sub-organization has a user holding `tvc.servicePublicKey` and a policy that
needs both that user and the owner, runs `bootstrap`, and approves only the
Turnkey activity that signs the exact bootstrap message. The example's
`approve` in [`lib.ts`](../../examples/typescript-client/src/lib.ts) and
[`bootstrap-approval.ts`](../../examples/typescript-client/src/bootstrap-approval.ts)
does this with the owner's Turnkey client.

### 5. Use the keys with the SDK

`keys` is the SDK's `WalletKeys`. Use it where an application would pass
`LocalKeys`:

```ts
import { Wallet, buildTransferTransaction, createSprClient, syncWallet } from "@heliuslabs/spr";
import { SignedTeePolicy } from "@heliuslabs/spr/client";

const spr = new URL("/api/helius/v1/spr", location.origin);
const client = await createSprClient({
  solanaRpcUrl, // the application's RPC URL
  indexerUrl: spr,
  proverUrl: spr,
  proverTee: SignedTeePolicy.forNetwork("devnet"),
  proofDataSource: "client", // the enclave completes proofs from data the client fetched
});
const wallet = new Wallet({ identity: keys.address() });
await syncWallet({ client, wallet, keys });
const transaction = await buildTransferTransaction({ client, wallet, keys, feePayer, recipient, amount });
```

The application signs and sends every transaction with the user's Turnkey
wallet, as any other Solana transaction. The enclave never signs one.

### What the user sees

- **Enrollment is silent.** On its first call, the client has the user's
  wallet sign an enrollment for the Turnkey session key, through the
  session, without a prompt.
- **One approval, once per wallet.** The first `open` without `stored`
  bootstraps the wallet, and the user approves it through `approve`. Later
  opens with `keys.stored` make no call.
- **Re-enrollment is silent.** A new login or a session refresh brings a new
  session key. The client enrolls it before the next request, and the stored
  wallet opens under it. An enrollment lasts a day and renews the same way.

### Keep `keys.stored` private

`keys.stored` holds the sealed seed. Together with a current session of the
wallet, it lets the holder decrypt the wallet's notes and complete its proofs
until that session's enrollment expires. It cannot sign a transaction. Store it like the user's session: only for that
user, and out of logs, analytics, crash reports and shared backups.

### Errors

The client's errors are `SprEmbeddedWalletError`s, exported from
`@heliuslabs/spr-embedded-wallet/protocol`, with a stable `code`. Compare
`code`, not the message.

- `SprEmbeddedWalletOperationError`: an operation ran and failed. `operation` names it and
  `stage` says where: `Prover` when the enclave refused the prover's policy
  or attestation, after one fresh attempt; `TurnkeySigning` when Turnkey
  declined to sign the bootstrap message.
- `SprEmbeddedWalletHttpError`: an HTTP failure, with `status` and the raw `retryAfter`
  header. On `429`, retry after `retryAfter`. The client does not repeat an
  operation, and a `5xx` does not prove that the operation did not run.
  `EnrollmentRejected` is the gateway refusing to enroll the session key,
  for example when the wallet's sub-organization is not named after the
  project.
- `TurnkeySessionRequired`: nobody is logged in to Turnkey.
- `ReleaseNotPinned`: `createSprEmbeddedWallet` was given a network this version
  pins no release for. This version pins devnet only.

### Limits

- Each wallet must be in a sub-organization of Helius's Turnkey
  organization, named after the Helius project of the API key.
- Per project, at most 16 sessions, enrollments and operations in flight and
  8 Turnkey calls at once. Above that, the gateway answers `429`.
- Each `/v1/private-wallet` call costs 200 credits: a session (the client's
  verification), an enrollment, or an operation. Each SDK call into `keys` is
  one operation per batch of up to 256 items. `/v1/spr` calls are billed
  separately.

## Reference

`createSprEmbeddedWallet({ network, endpoint, turnkey, solanaAddress?, prover?, nowMs?, transport?, requestTimeoutMs? })`:

- `endpoint` is the network's tvc-gateway: a route on the application's own
  origin that forwards to `https://<network>.helius-rpc.com/v1/private-wallet`
  and adds the API key on the server, as above, or that URL itself with
  `?api-key=…` on a server. Its query travels on every route.
- `turnkey` is the application's Turnkey client with a logged-in session:
  `@turnkey/core`'s `TurnkeyClient`, or what `useTurnkey()` returns in
  `@turnkey/react-wallet-kit`, as it is. The client uses four of its methods,
  typed as `SprEmbeddedWalletTurnkey`: `getSession`, `signWithApiKey`, `fetchWallets` and
  `signMessage`. A server implements them over a Turnkey API key; see
  [the example](../../examples/typescript-client/src/lib.ts).
- `solanaAddress` names the wallet when the session's organization holds more
  than one embedded Solana account; by default the client takes the only one.
- `prover` is the attested prover the enclave seals proofs to and the client
  posts them to. It defaults to `/v1/spr` on the endpoint's origin with the
  endpoint's query, where Helius serves the network's TEE prover.
- `transport` carries every HTTP request the client makes: the gateway, the
  prover and the prover's policy file.

`tvc.open(stored?, { approve?, signal?, timeoutMs? })` returns `SprEmbeddedWalletKeys`, the
SDK's `WalletKeys`, with `keys.stored` to persist.

`keys.stored` is sensitive. Its sealed seed opens the wallet's privacy keys
inside the enclave under any descriptor of the wallet: with a current
descriptor and its client key, such as a stolen session, it lets the holder
decrypt the wallet's notes, derive its nullifiers and complete its proofs
until that descriptor expires, and with tvc-gateway's provisioning key, which
issues descriptors, for as long as that key does. It cannot sign a
transaction.

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
[`crates/protocol`](../../crates/protocol/README.md), stay behind `SprEmbeddedWalletKeys`
and `open`. No operation returns a long-lived secret, none signs a Solana
transaction, and none takes a caller-selected network origin.

## Networks

`network`, `devnet` or `mainnet`, is the network the enclave serves, and the
client is for that network only:

- The release it verifies the enclave against is this package's
  `src/releases/<network>.json`, which `scripts/release.mjs` writes and
  tvc-gateway reads. A file that is `null` pins no release, and
  `createSprEmbeddedWallet` throws `ReleaseNotPinned` for its network.
  `createTestSprEmbeddedWallet` in `./testing` takes another release for a test
  deployment.
- The signed policy names its network, and verification refuses a policy, or
  a `/v1/info`, for another (`NetworkMismatch`). Operations refuse a wallet
  descriptor for another network before they sign.
- Proofs go under the network's signed prover policy file.
- `walletEnrollmentMessage` signs for the gateway's network as its chain.

`SprEmbeddedWalletKeys` is the same surface as the SDK's `WalletKeys`. It splits the items
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
wait. `SprEmbeddedWalletKeys`
fetches the prover's attestation for a fresh nonce (`GET <url>/attestation`)
and reuses it for the same `max_age_secs`, asks the enclave to complete the
request and seal it to the attested key under that file, and posts the sealed
request to `<url path>/prove/<key>` with the URL's query, such as its API key.
It opens the answer with the response key the enclave returned, which opens
nothing else. When the enclave refuses the policy or attestation (a
`SprEmbeddedWalletOperationError` with `stage: "Prover"`), or the prover answers
`tee_decryption_failed`, the client downloads the policy again, attests again
and seals once more. Neither the client nor any proxy in front of
the prover holds the witness in plaintext.

The enclave binds a sealed request to its route below the prover's URL,
`/prove/<key>`, so a gateway or proxy may serve the prover on any path. It must
forward the request with its `Spr-Tee` headers and body unchanged.

Prover failures, including encrypted failures, retain their status and
`Retry-After` as `SprEmbeddedWalletHttpError`. They are returned without automatically
repeating the proof; only the explicit key-loss response triggers the bounded
reattestation flow. Configure the proxy to disable unsafe-method retries
(`disableUnsafeRetries: true` in Gatekeeper). A 5xx can follow execution and
does not establish that the proof or a signed operation never ran.

`snapshotCipher(keys, context?)` is the SDK's `WalletStateCipher` for
`syncPersistedWallet` and `loadPersistedWallet`. Its key is a per-transaction
key the enclave mints under a context no transaction can have, so a sealed
wallet snapshot persists at rest and reopens on any device that can drive this
wallet's enclave operations.

`open` takes `{ signal, timeoutMs }`, and `SprEmbeddedWalletKeys` forwards the SDK's
`RequestContext`. Each bounds the verification and the operation, each
defaulting to two minutes, including request signing, reading the response,
and Boot Proof lookup. Set `requestTimeoutMs` in the client configuration to
change that default. Concurrent callers share one verification; cancelling one
does not cancel another. When all callers leave, the verification stops and a
late response cannot replace a newer one.

Snapshot loading accepts the SDK's `RequestContext` and destroys temporary key
material on success, failure, or cancellation. HTTP failures are `SprEmbeddedWalletHttpError`
instances with `status` and the raw `retryAfter` header. An operation that ran and
failed at a named stage is a `SprEmbeddedWalletOperationError` with its `operation` and `stage`
(`Prover`, or `TurnkeySigning` when Turnkey declined the bootstrap signature).
The client does not retry a failed operation automatically.

## The session key

The client key is the Turnkey session key. Turnkey's client holds a
non-exportable P-256 key for each login session. The client signs every
request with it through `signWithApiKey`, over the client-auth text
`spr-tvc-client-auth-v1:<request digest, lowercase hex>` (ECDSA P-256 over
SHA-256), normalizes the signature to low S, and checks it against the key
before it sends. Its `signWithApiKey` calls on one Turnkey client run one at
a time: `@turnkey/core` points the stamper at the given key for each call and
restores the previous key afterwards, so overlapping calls could leave the
application's stamper on a stale key. An application that calls
`signWithApiKey` itself should not overlap it with the client's requests.

On first use the client enrolls the key with the gateway. It finds the
wallet's Solana account (`fetchWallets`; connected wallets are skipped), has
the wallet sign `walletEnrollmentMessage` with Ed25519 (`signMessage`, a text
payload, unhashed), a Sign-In With Solana message for the network's gatekeeper host
(`ENROLLMENT_DOMAINS[network]`, whatever host `endpoint` names, so a proxy
works) whose chain is the network, and posts
`{organizationId, turnkeyWalletId, solanaAddress, clientPublicKey, issuedAtMs, ownerSignature}`
to `<endpoint>/enroll`. The gateway answers a descriptor for the key, which
the client checks and keeps in memory for that key. Concurrent first calls
share one enrollment. Cancelling every one of them stops it only until the
owner has signed; after that the client finishes it and keeps the descriptor,
so the owner never signs twice for one key. A descriptor lives a day (the
gateway's `descriptor_ttl_secs`) from the enrollment: the client enrolls the
key again before a request once its descriptor expires within five minutes,
and once more, repeating the request, when the gateway or the enclave refuses
it as expired (`DescriptorExpired`, a `SprEmbeddedWalletHttpError` with status 403 if it
persists). A new login, or
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

- `@heliuslabs/spr-embedded-wallet`: `createSprEmbeddedWallet`, `SprEmbeddedWalletTurnkey`,
  `SprEmbeddedWalletKeys`, `parseStoredWallet` and `snapshotCipher`.
- `@heliuslabs/spr-embedded-wallet/protocol`: wire types, `SprEmbeddedWalletError`, hex codecs,
  `clientKeyIdFor`, and `walletEnrollmentMessage`, the Sign-In With Solana
  message the wallet signs to enroll a key with tvc-gateway.
- `@heliuslabs/spr-embedded-wallet/testing`: `createTestSprEmbeddedWallet`, which
  verifies an enclave as `createSprEmbeddedWallet` does against a release and backend
  the caller names (a gateway, or the enclave itself with
  `{ kind: "enclave", endpoint, resolveBootProof, walletGrant }`), with the
  Turnkey session or a descriptor and the signer of its key
  (`createSprRequestSigner`), `createLocalSprEmbeddedWallet`, the loopback-only
  unattested testkit client for the network the testkit was built for, and
  `verifyLiveReplica`, which `scripts/release.mjs` runs on a live replica
  before it signs that replica's release policy. The build fails if testkit
  code becomes reachable from a production entry.

## Development

From the repository root:

```sh
pnpm ci:ts
```
