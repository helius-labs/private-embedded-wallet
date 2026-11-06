# tvc-gateway

Helius-hosted backend for the Zolana private embedded wallet. It gives any
Helius customer the private-wallet backend with only an API key, at
`/v1/private-wallet/*` behind gatekeeper or directly. It fronts:

- the Zolana TVC enclave (`apps/privacy-wallet`),
- Turnkey (Boot Proofs and wallet ownership),

and holds the provisioning key that signs wallet descriptors. The Zolana
indexer and prover are gatekeeper's own `/v1/spr/*` routes.

Each deployment serves one network, `devnet` or `mainnet`, in front of that
network's enclave, and issues descriptors only for it. One image serves
either; the config names the network.

## Request flow

```
client (browser, mobile or server, Helius API key)
  → helius-router → gatekeeper   (API key, domain ACL, rate limit, billing)
  → tvc-gateway                  (Authorization: gatekeeper origin secret,
                                  X-Helius-Project-Id: caller's project)
  → enclave / Turnkey

client (Helius API key as ?api-key= or X-Api-Key)
  → tvc-gateway                  (project from Helius dev-api's GET /waas/config)
  → enclave / Turnkey
```

A request with an `Authorization` header must carry gatekeeper's origin
value, and only then is `X-Helius-Project-Id` trusted. Any other request needs
a Helius API key, which the gateway resolves to its project through Helius
dev-api (`ts-services/dev-api` in helius-labs/monorepo) at `dev_api.base_url`,
and caches for `dev_api.project_cache_secs`. dev-api serves only projects on
a paid plan in the WaaS rollout: an unknown key is `401 ApiKeyInvalid`, any
other project `403 WaasNotEnabled`, and both refusals are cached for 30
seconds. dev-api throttles the route to 30 requests a minute per caller IP,
which every lookup from one gateway task shares. A direct request is not metered and gets none of
gatekeeper's per-key limits.

## Endpoints

All paths are under `/v1/private-wallet`, and all take the caller's project
from gatekeeper or from the caller's API key.

| Method | Path          | Body                                        | Answer                     |
| ------ | ------------- | ------------------------------------------- | -------------------------- |
| POST   | `/session`    | the enclave's ping request                  | `{info, ping, bootProof}`  |
| POST   | `/enroll`     | an owner-signed enrollment                  | `{descriptor}`             |
| POST   | `/operations` | `{descriptor, request}`                     | `{response, bootProof}`    |

`GET /health` needs no credentials. [`openapi.json`](openapi.json) is the
OpenAPI 3.1 document of the API as gatekeeper serves it. A test fails when it
is stale; `BLESS_OPENAPI=1 cargo test` rewrites it.

Failures are RFC 9457 problems, `application/problem+json`:
`{"title", "status", "detail", "code"}`, where `code` is one of the codes the
OpenAPI document lists. `429` and `409 OperationInProgress` carry
`Retry-After`. A non-success enclave answer is passed through. Once a request
has reached the enclave or Turnkey, dependency failures are `424`. This status
is not a substitute for replay protection: a load balancer may return a 5xx
after an operation ran. The gateway owns the replay ledger described below.

For the backend in [monorepo #20892](https://github.com/helius-labs/monorepo/pull/20892),
configure `forwardProjectId: true`, `disableUnsafeRetries: true`, and response
headers `cache-control`, `retry-after`, `idempotent-replayed`, alongside the
Authorization origin secret. Use the shared Redis ledger across replicas.
Heimdall forwards opaque requests and trusted project identity; it does not
interpret wallet operations or decide which ones may be repeated.

### Session

The body is the enclave's `POST /v1/ping` request: a challenge encrypted to the
release's quorum key. The gateway sends it to the enclave with `GET /v1/info`,
and answers with both enclave answers and the Turnkey Boot Proof of the replica
that signed the ping. The client verifies all three; the gateway vouches for
none of them.

### Enrollment

The wallet owner signs, with the wallet's Ed25519 key through Turnkey, a
[Sign-In With Solana](https://github.com/phantom/sign-in-with-solana) message:

```
beta-devnet.helius-rpc.com wants you to sign in with your Solana account:
<solanaAddress>

Authorize this device key to use your private wallet.

Version: 1
Chain ID: <network>
Issued At: <issuedAtMs as RFC 3339>
Expiration Time: <five minutes later>
Resources:
- urn:turnkey:organization:<organizationId>
- urn:turnkey:wallet:<turnkeyWalletId>
- urn:zolana-tvc:client-key:<clientPublicKey>
```

The first line names the host the client called, one of
`enrollment.domains`, and the chain is the gateway's network, `devnet` or
`mainnet`, so a signature enrolls at this gateway only. `walletEnrollmentMessage` in `@heliuslabs/spr-embedded-wallet/protocol`
builds the message. `fixtures/wallet-enrollment.json`, from
`createSignInMessageText` in `@solana/wallet-standard-util`, is its test
vector.

`POST /enroll` with
`{organizationId, turnkeyWalletId, solanaAddress, clientPublicKey, issuedAtMs, ownerSignature}`.
The gateway checks:

- that the release it issues descriptors under has not expired (`503 ReleaseExpired`);
- that `issuedAtMs` is at most 5 minutes old and at most 60 s ahead;
- the signature;
- that the Turnkey sub-org is named after the caller's project;
- that the wallet account has the claimed address.

It answers `{descriptor}`, signed with the provisioning key for that one client
key. Enrolling again answers the same descriptor.

### Operations

`request` is the enclave's `EncryptedRequest` without `wallet_grant`. The
gateway checks:

- that it signed the descriptor, and that its client key is not revoked;
- that no request sent the ciphertext before;
- that the descriptor's Turnkey sub-org is named after the caller's project.

It then adds a wallet grant, the protocol's `WalletGrant`
(`crates/protocol/README.md`), signed with the grant key for this descriptor
and project and valid for `wallet_grant.ttl_secs`. The enclave checks the grant
names the request's descriptor and client key. The answer is the enclave's
`EncryptedResponse` and the Boot Proof of the replica that answered.

A resent ciphertext does not run twice. From the same project within
`enclave.replay_window_secs`, it gets the first request's answer again,
marked `Idempotent-Replayed: true`, or `409 OperationInProgress` while the
first is still running. From another project it gets `409 ReplayedRequest`.
A request that never reached the enclave, refused by the ownership check for
example, can be resent.

To revoke a client key, add its `tvc-browser-p256-…` ID to
`wallet_grant.revoked_client_key_ids`. The gateway refuses its enrollments and
operations from the next deploy.

### Limits

- **In-flight enclave calls:** at most `enclave.max_in_flight_per_project` per project (`429`).
- **Turnkey calls:** at most 32 at once across all projects (`429`); both Turnkey keys are shared.
- **Resends:** the replay ledger keys each `/operations` ciphertext by its digest, however its JSON is encoded. With `enclave.replay_redis_url` set, every task shares it through Redis, claiming with one `SET key running NX GET EX`, and it survives restarts; an unreachable Redis refuses the request with `424`. Without it, each process keeps its own.
- **Body size:** `enclave.max_body_bytes`.

## Configuration

The gateway runs with one network's overlay, `--config configs/devnet.yaml` or
`--config configs/mainnet.yaml`. It loads `config.yaml` from the overlay's
directory with the settings every network shares, then the overlay with the
network's own: `network`, `enclave.base_url`, `turnkey.tvc_organization_id`,
both `expected_public_key`s, `enrollment.domains` and
`provisioning.release_path`. `configs/mainnet.yaml` names no enclave or
Turnkey organization yet, so a mainnet gateway refuses to start until they are
set. Secrets come from `TVC_GATEWAY_*` environment variables, which override
either file, with nested fields joined by `__`:

| Variable                                                          | Value                                                                                     |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `TVC_GATEWAY_ORIGIN_AUTH_HEADER`                                  | The `Authorization` value gatekeeper sends, 32 bytes or more. Always required.            |
| `TVC_GATEWAY_PROVISIONING__PRIVATE_KEY`                           | Provisioning P-256 secret, hex. Must match `provisioning.expected_public_key`.            |
| `TVC_GATEWAY_WALLET_GRANT__PRIVATE_KEY`                           | Wallet-grant P-256 secret, hex. Must match `wallet_grant.expected_public_key`.            |
| `TVC_GATEWAY_ENCLAVE__REPLAY_REDIS_URL`                           | Optional. Redis for the shared replay guard, such as `rediss://host:6379/2`.              |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__{PUBLIC,PRIVATE}_KEY`   | Turnkey API key in the TVC organization that can read Boot Proofs.                        |
| `TVC_GATEWAY_TURNKEY__WAAS_API_KEY__{PUBLIC,PRIVATE}_KEY`         | Turnkey API key in the Helius WaaS parent organization, with read access to its sub-orgs. |

`enrollment.domains` are the hosts clients reach the gateway at, gatekeeper's
`devnet.helius-rpc.com` and `beta-devnet.helius-rpc.com` on devnet and
`mainnet.helius-rpc.com` and `beta-mainnet.helius-rpc.com` on mainnet; an
enrollment message names the one the client called. `dev_api.base_url` is the
Helius dev-api that resolves a direct caller's API key.

`provisioning.release_path`, `releases/<network>.json` relative to the working
directory, is the network's release file as clients pin it
(`packages/tvc-wallet/src/releases/`, copied to `/app/releases/` in the
image): the signed release policy that descriptors are issued under and the
authority set it must verify against. The service refuses to start if the
policy is for another network or does not verify, and stops enrolling once it
expires.

**When a new enclave release ships:** the release writes the network's file;
publish a new image and redeploy.

## Development

The crate is outside the root workspace, so the Turnkey client and server
graph stay out of the enclave build. `just fmt`, `just lint` and `just test`
cover it. Directly:

```sh
cargo clippy --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked
```

To run it, from `apps/tvc-gateway`:

```sh
TVC_GATEWAY_PROVISIONING__RELEASE_PATH=../../packages/tvc-wallet/src/releases/devnet.json \
  TVC_GATEWAY_...=... cargo run -- --config configs/devnet.yaml
```

### Local end to end

```sh
just gateway-e2e
```

Runs `e2e/`, a vitest suite, on loopback. Its global setup (`e2e/stack.ts`)
starts:

- the local unattested testkit enclave (`zolana-tvc-privacy-wallet-local`), with fixed test keys and mock custody;
- a mock Turnkey answering the ownership and Boot Proof queries (`e2e/mock-turnkey.ts`);
- the gateway, with a release file from `cargo run -p zolana-tvc-protocol --example sign-release-policy -- --local-testkit <dir>`.

The tests send the headers gatekeeper would add and drive a wallet through
the testkit client in gateway mode: enrollment, one session, Bootstrap,
TransactionKeys and a resend answered with the first answer, and the refusals
of stale, forged, other-domain and other-project enrollments, other projects'
wallets and resends, and descriptors this gateway did not provision. CI runs it after `just ci`. Service logs go to a temporary
directory the run prints.

`fixtures/wallet-enrollment.json` is the enrollment message test vector that
both this crate and `walletEnrollmentMessage` in `@heliuslabs/spr-embedded-wallet` check.

## Deployment

The service runs on AWS as ECS Fargate tasks in each of zolana-infra's
network stacks (`infra/modules/zolnet/ecs_tvc_gateway.tf`), behind that
stack's ALB and a CloudFront distribution of its own. The image runs
`--config /app/configs/devnet.yaml` by default; a mainnet task overrides the
command with `--config /app/configs/mainnet.yaml`.

1. Run the `publish-tvc-gateway-image` workflow. It pushes to the zolnet ECR
   repository `zolnet-tvc-gateway`, and its summary prints the `tvc_gateway_image`
   digest reference.
2. Pin that reference as `tvc_gateway_image` in zolana-infra's
   `infra/envs/<env>/main.tf`, with `enable_tvc_gateway = true`, then deploy
   the env.
3. Populate the `zolnet-<env>/tvc-gateway` secret, as described in zolana-infra's
   `infra/README.md`.

The container needs `TVC_GATEWAY_LISTEN=0.0.0.0:8940`, since the shipped config
listens on loopback, and `TVC_GATEWAY_STAGE=prod` for JSON logs. The zolana-infra
task definition sets both. The enclave timeout is 55s, under CloudFront's 60s
origin read timeout.

## Metrics

statsd, prefix `tvc_gateway`:

- `request.latency`, tagged by `route` and `status`.
- `upstream.latency`, tagged by `target` and `status`.
- `upstream.failed`.
- `turnkey.rejected` and `turnkey.failed`, tagged by `call`.
- `ownership.rejected`, tagged by `reason`.
- `enclave.in_flight_rejected`.
- `enclave.replay_rejected`: another project resent a ciphertext.
- `operations.replayed` and `operations.in_progress`: a resend got the first answer, or found it still running.
- `enclave.replay_guard_unavailable` and `enclave.replay_guard_early_rotation`.
- `turnkey.concurrency_rejected` and `upstream.response_too_large`.
- `origin_auth_rejected`.
- `api_key.cache_hit`, `api_key.rejected` (tagged by `reason`) and `api_key.lookup_failed`.
- `boot_proof.cache_hit`.
