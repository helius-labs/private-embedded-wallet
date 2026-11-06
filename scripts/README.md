# Operator tooling

| Script | Purpose |
| --- | --- |
| [`release.mjs`](release.mjs) | Deploys and signs a release of one network's privacy-wallet enclave, then pins it in tvc-wallet's `src/releases/<network>.json`, which tvc-gateway reads too. |
| [`create-service-key.mjs`](create-service-key.mjs) | Creates a P-256 service key (provisioning or wallet grant) straight into a new AWS Secrets Manager secret with the `aws` CLI and prints only its public key, the value the enclave pins. |
| [`start-localnet.sh`](start-localnet.sh) | Starts a Zolana localnet for `just headless-e2e`. |

The scripts need Node 24, Docker with `linux/amd64`, cargo, and the Turnkey
`tvc` CLI logged in to the app's organization. Nothing here holds a key longer than
one call. Never commit Turnkey operator files, API keys, or `.env.local`.

## Release

Each network, `devnet` or `mainnet`, has its own Turnkey TVC app, Quorum key,
operators, `linux/amd64` image pinned by `@sha256:`, signed release policy,
and wallet descriptors.
[`apps/privacy-wallet/deploy/release.json`](../apps/privacy-wallet/deploy/release.json)
holds the constants: the image repository, QOS version and PCRs, trust root,
proof schemas and policy lifetime at the top, and each network's app, endpoint,
security domain, Quorum key and operators under `networks.<network>`. A network
without an entry has no Turnkey app yet, and the script refuses it; mainnet
has none today. Each network's deployment files live in
`apps/privacy-wallet/deploy/<network>/`.

The `publish-privacy-wallet-image` workflow builds the image of a commit for one
network (`devnet` or `mainnet`, the keys and signed prover policy the image
trusts) into the public GHCR package `imageRepository`, tagged
`privacy-wallet-<network>-<commit>`, and its run summary has the reference
pinned by digest and the `/tvc_app` SHA-256. `just image-privacy-wallet
<network>` builds the same image locally to compare against.

```sh
just release devnet private-wallet-devnet-<sha> --image <reference>
node scripts/release.mjs policy private-wallet-devnet-<sha> --network devnet   # one phase
```

`--network` is required and names the network in every phase.

| Phase | What it does |
| --- | --- |
| `build` | Refuses an image not tagged for the network, reads the `/tvc_app` SHA-256 from the `--image` reference and records it (`expectedPivotDigest`) with the reference in `deploy/<network>/privacy-wallet-<release>.deployment.json`. Debug mode stays off; `qosVersion` equals the pinned `qos_core`. |
| `deploy` | Drives the `tvc` CLI: creates the deployment, collects one approval per operator, provisions it, sets it live, and waits until `/v1/info` serves the release. Each approval shows the QOS manifest for the operator to confirm; `--unattended` skips that review and is refused on mainnet. A re-run continues from the last completed step. |
| `policy` | Checks that `/v1/info` serves the network and the release's constants, assembles the release policy, signs it with a one-time authority key (`cargo run -p zolana-tvc-protocol --example sign-release-policy`, which verifies the signed policy for its network before it answers; the private half exists only inside that call), and writes the policy, the authority public keys and the QOS identity PCRs to tvc-wallet's `src/releases/<network>.json`, replacing what was there (`null` for a network with no release yet). The client exports it as `RELEASES[network]`, and tvc-gateway's image carries it as its release file. |

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
