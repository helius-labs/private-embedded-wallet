# `@heliuslabs/spr-embedded-wallet`

Client for the TVC privacy wallet of Solana Privacy Rings. It verifies the signed release policy
and the AWS Nitro Boot Proof before handing out a `VerifiedConnection`, wraps
every operation in a QOS P-256 envelope, checks the proof-bound result, and
answers the Zolana SDK's `WalletKeys` interface through `TvcKeys`, so every
`@heliuslabs/spr` flow runs over the enclave unchanged.

Pre-production. Requires `@heliuslabs/spr` 0.9.0-alpha or later, which
speaks the `/v1/spr` prover contract and its signed policies.

## Usage

```ts
import {
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  createSprClient,
  syncWallet,
} from "@heliuslabs/spr";
import { SignedTeePolicy } from "@heliuslabs/spr/client";
import { AssetRegistry } from "@heliuslabs/spr/transaction";
import {
  DEVNET_RELEASE,
  TvcKeys,
  TvcProverPolicy,
  sealedSeedOf,
  createTvcClient,
  identityOf,
  shieldedAddressOf,
} from "@heliuslabs/spr-embedded-wallet";

const tvc = createTvcClient({ ...DEVNET_RELEASE, ...config }); // + backend, descriptor, authorizer
const connection = await tvc.connectAndVerify();

// Once per wallet; also the recovery path after the sealed seed is lost or the Quorum key rotates.
const bootstrap = await tvc.bootstrap(connection, { expectedIdentity: stored ?? undefined });
const identity = identityOf(bootstrap); // persist
const sealedSeed = sealedSeedOf(bootstrap); // persist; presented on every later call

// The enclave as the SDK's keys. Nothing below learns a secret: a proof's witness
// is sealed inside the enclave to the attested prover at `prover.url`, under the
// signed policy of the network the enclave image was built for.
const keys = new TvcKeys({
  client: tvc,
  connection,
  sealedSeed,
  identity,
  prover: {
    url: proverUrl, // a regional TEE prover, or a gateway's `/v1/spr`
    policy: TvcProverPolicy.forNetwork("devnet"),
  },
});
// The enclave completes resolved proof inputs; it has no indexed proving, so the
// client fetches the proof data itself.
const zolana = await createSprClient({
  solanaRpcUrl,
  indexerUrl,
  proverUrl,
  proverTee: SignedTeePolicy.forNetwork("devnet"),
  proofDataSource: "client",
});
const wallet = new Wallet({
  identity: shieldedAddressOf(identity),
  registry: new AssetRegistry([[assetId, mint]]),
});

await syncWallet({ client: zolana, wallet, keys });
const transaction = await buildTransferTransaction({
  client: zolana,
  wallet,
  keys,
  feePayer: solanaSigner.address,
  recipient,
  amount,
});
// Sign with the wallet's Solana signer (a Turnkey session, a keypair) and submit.
```

`TvcClient` has exactly `connectAndVerify`, `bootstrap`, `decrypt`, `derive`,
`transactionKeys`, and `prove`: the wire form of the five enclave operations,
specified in [`crates/protocol`](../../crates/protocol/README.md). No
operation returns a long-lived secret, none signs a Solana transaction, and
none takes a caller-selected network origin.

`TvcKeys` is the same surface as the SDK's `WalletKeys`. It splits the items
of one SDK call into batches of at most 256, splits further when the full
serialized HTTP envelope exceeds the advertised request byte limit, and forwards the SDK's
`RequestContext` (abort signal and timeout) to every batch, so a cancelled
sync stops its decrypt batches as a cancelled build stops its proof. The pool
cipher is unauthenticated, so the SDK adopts a decrypted UTXO only when its
commitment matches the indexed output.

A proof is at most three calls after the policy file. `TvcProverPolicy`
downloads the network's signed policy file and holds it for its
`max_age_secs`; the enclave, not the client, checks its signatures. `TvcKeys`
fetches the prover's attestation for a fresh nonce (`GET <url>/attestation`)
and reuses it for the same `max_age_secs`, asks the enclave to complete the
request and seal it to the attested key under that file, and posts the sealed
request to `<url path>/prove/<key>` with the URL's query, such as its API key.
It opens the answer with the response key the enclave returned, which opens
nothing else. When the enclave refuses the policy or attestation, or the
prover answers `tee_decryption_failed`, the client downloads the policy again,
attests again and seals once more. Neither the client nor any proxy in front of
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

`connectAndVerify` and every enclave operation accept `{ signal, timeoutMs }`.
They default to two minutes, including request authorization, reading the response,
and Boot Proof lookup. Set `requestTimeoutMs` in the client configuration to change
that default. Concurrent verification callers share the work; cancelling one does
not cancel another. When all callers leave, the request stops and a late response
cannot replace a newer verified connection.

Boot Proof resolvers receive `signal` in their input; forward it to their fetch.
Snapshot loading accepts the SDK's `RequestContext` and destroys temporary key
material on success, failure, or cancellation. HTTP failures are `TvcHttpError`
instances with `status` and the raw `retryAfter` header. The client does not retry
a failed operation automatically.

## Backends

`backend` says where the client reaches the enclave. Through either, the
client verifies the same evidence.

- `{ kind: "gateway", endpoint }` is a tvc-gateway, such as
  `https://beta-devnet.helius-rpc.com/v1/private-wallet?api-key=…`. One
  `/session` request answers discovery, the ping and the Boot Proof, every
  operation response carries its replica's Boot Proof, and the gateway grants
  each operation.
- `{ kind: "enclave", endpoint, resolveBootProof, walletGrant }` is the enclave
  itself. `resolveBootProof` fetches each replica's Boot Proof, and
  `walletGrant` supplies a current grant for every request.

```ts
const tvc = createTvcClient({
  backend: { kind: "gateway", endpoint: new URL(gatewayUrl) },
  releasePolicy,
  releaseAuthorities,
  qosIdentityPcrs,
  operations: { walletDescriptor, authorizer },
});
```

A gateway descriptor comes from `POST {endpoint}/enroll`: the wallet owner
signs `walletEnrollmentMessage(enrollment)`, a Sign-In With Solana message
whose `domain` is the endpoint's host, with the wallet's Solana key, and the
gateway answers `{descriptor}` for the enrollment's client key. See
[`apps/tvc-gateway`](../../apps/tvc-gateway/README.md#enrollment).

## Entry points

- `@heliuslabs/spr-embedded-wallet`: client, `TvcKeys`, `snapshotCipher`, release-policy
  verification, and `createTvcOperationAuthorizer` for a caller-held P-256
  request key outside the browser.
- `@heliuslabs/spr-embedded-wallet/protocol`: wire types, `TvcError`, hex codecs,
  `clientKeyIdFor`, and the provisioner's side of a wallet descriptor:
  `signWalletDescriptor` builds and signs the grant for one client key from the
  release policy, `verifyWalletDescriptor` checks one, `provisioningSecret` reads the provisioning key and refuses
  one the enclave was not built with. The wallet-grant issuer's side:
  `walletGrantSecret` reads the grant key and refuses one the enclave was not
  built with, `signWalletGrant`, and `verifyWalletGrantRenewal` for a
  self-hosted issuer's renewal (`walletGrantRenewalMessage`).
  `walletEnrollmentMessage` is the Sign-In With Solana message a wallet owner
  signs to enroll with tvc-gateway.
- `@heliuslabs/spr-embedded-wallet/browser`: non-exportable P-256 request signer, which
  also signs grant renewals for its own descriptor (`signWalletGrantRenewal`),
  the persisted enclave-state parser, and IndexedDB record helpers.
- `@heliuslabs/spr-embedded-wallet/react`: `TvcWalletProvider` / `useTvcWallet` for the
  connection lifecycle.
- `@heliuslabs/spr-embedded-wallet/testing`: loopback-only unattested testkit client. The
  build fails if it becomes reachable from a production entry.

## Verification

From the repository root:

```sh
pnpm ci:ts
```
