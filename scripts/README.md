# Operator tooling

| Script | Purpose |
| --- | --- |
| [`release.mjs`](release.mjs) | Deploys and signs a release of one network's enclave application, then pins it in tvc-wallet: the privacy wallet in `src/releases/<network>.json`, which tvc-gateway reads too, the decryption service in `src/decryption-service/releases/<network>.json`. |
| [`create-service-key.mjs`](create-service-key.mjs) | Creates a P-256 service key (provisioning or wallet grant) straight into a new AWS Secrets Manager secret with the `aws` CLI and prints only its public key, the value the enclave pins. |
| [`start-localnet.sh`](start-localnet.sh) | Starts a Zolana localnet for `just headless-e2e`. |

The scripts need Node 24, Docker with `linux/amd64`, cargo, the Turnkey
`tvc` CLI logged in to the app's organization, and a built tvc-wallet
(`pnpm build:ts`), whose verifier the `policy` phase runs. Nothing here holds a
key longer than one call. Never commit Turnkey operator files, API keys, or `.env.local`.

## Release

Each application, `privacy-wallet` or `decryption-service`, has on each
network, `devnet` or `mainnet`, its own Turnkey TVC app, Quorum key, operators,
`linux/amd64` image pinned by `@sha256:` and signed release policy.
`apps/<app>/deploy/release.json`
([privacy wallet](../apps/privacy-wallet/deploy/release.json),
[decryption service](../apps/decryption-service/deploy/release.json)) holds the
constants: the cargo package, image repository, QOS version and PCRs, trust
root, proof schemas and policy lifetime at the top, and each network's app,
endpoint, security domain, Quorum key and operators under `networks.<network>`.
A network without an entry has no Turnkey app yet, and the script refuses it.
Each network's deployment files live in `apps/<app>/deploy/<network>/`.

The `publish-enclave-image` workflow builds one application's image of a
commit for one network into the public GHCR package `imageRepository`, tagged
`<app>-<network>-<commit>`, and its run summary has the reference pinned by
digest and the `/tvc_app` SHA-256. `just image <app> <network>` builds the same
image locally to compare against.

```sh
just release devnet private-wallet-devnet-<sha> --image <reference>
node scripts/release.mjs policy private-wallet-devnet-<sha> --network devnet   # one phase
just release devnet decryption-service-devnet-<sha> --app decryption-service --image <reference> \
    --operator-seeds <dir> --quorum-key-metadata <file>
```

`--network` is required and names the network in every phase. `--app` is the
privacy wallet unless given.

The decryption service has a local Quorum key: `tvc keys
generate-local-quorum-key` made it, and its shares, each encrypted to one
operator, are in a `quorum_key_metadata.json` kept outside Turnkey and this
repository. An operator approves and provisions with its own key, so `deploy`
takes the directory of the key files present, `operator-<n>.seed` for the n-th
of `operatorIds`, and the metadata file. A threshold of operators is enough.

| Phase | What it does |
| --- | --- |
| `build` | Refuses an image not tagged for the application and network, reads the `/tvc_app` SHA-256 from the `--image` reference and records it (`expectedPivotDigest`) with the reference in `deploy/<network>/<app>-<release>.deployment.json`. Debug mode stays off; `qosVersion` equals the pinned `qos_core`. |
| `deploy` | Drives the `tvc` CLI: creates the deployment, collects one approval per operator, provisions it (a hosted share with `tvc deploy provision`, a local one re-encrypted to the attested enclave and posted), sets it live, and waits until `/v1/info` serves the release. Each approval shows the QOS manifest for the operator to confirm; `--unattended` skips that review and is refused on mainnet. A re-run continues from the last completed step. |
| `policy` | Checks that `/v1/info` serves the network and the release's constants, then verifies the live replica as a client would, with tvc-wallet's `verifyLiveReplica` (`./testing`): it answers a challenge sealed to the Quorum key `/v1/info` reports, and its Boot Proof, fetched from Turnkey with the `tvc` login's API key (`TVC_ORG_ID`, `TVC_API_KEY_PUBLIC`, `TVC_API_KEY_PRIVATE`, or the active organization of `~/.config/turnkey/tvc.config.toml`), chains to the pinned AWS Nitro root, carries `qosIdentityPcrs` and attests the reported manifest digest, under the trust root `turnkeyTrustRootId` names. A replica that does not verify stops the phase before anything is signed. Only then it assembles the release policy, signs it with a one-time authority key (`cargo run -p spr-tvc-protocol --example sign-release-policy`, which verifies the signed policy for its network before it answers; the private half exists only inside that call), and writes the policy, the authority public keys and the QOS identity PCRs to the application's release file in tvc-wallet, replacing what was there (`null` for a network with no release yet). The client exports it as `RELEASES[network]`, and tvc-gateway's image carries it as its release file. |

Commit `deploy/<network>/` and the release file, then publish a tvc-gateway
image and redeploy the network's gateway.

Turnkey keeps three deployable deployments per app. `--prune-deployments`
deletes the oldest that are neither live nor the release's own until the new
one fits. Every Turnkey call goes through the `tvc` CLI and its active login.

The [protocol specification](../crates/protocol/README.md#release-policy)
defines the policy and its signature. Re-signing means a new authority set
every client must accept. The gateway end-to-end suite signs a policy for the
local testkit through the script's `releasePolicy` and `signReleasePolicy` and
checks that the client accepts it for the testkit's network only.

## Localnet

`start-localnet.sh PORT_OFFSET SOLANA_KEYPAIR FIXTURE_DIR OUTPUT_ENV` builds
the programs, Photon, the prover, and the CLI from a sibling `../zolana`
checkout, starts a validator with the shielded pool, Photon, and the prover on
the offset ports, mints a test SPL asset, and writes the `SPL_*` values the
client example reads to `OUTPUT_ENV`. `just headless-e2e` runs it. The sibling checkout must
be at the zolana commit
[`headless-local-e2e.yml`](../.github/workflows/headless-local-e2e.yml) pins,
the `gitHead` of the `@heliuslabs/spr` release the packages depend on.
