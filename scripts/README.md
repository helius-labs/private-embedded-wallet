# Operator tooling

| Script | Purpose |
| --- | --- |
| [`release.mjs`](release.mjs) | Deploys and signs a release of the privacy-wallet enclave, then pins it in tvc-wallet and tvc-gateway. |
| [`provision-descriptor.mjs`](provision-descriptor.mjs) | Signs a wallet descriptor for one client key. |
| [`start-localnet.sh`](start-localnet.sh) | Starts a Zolana localnet for `just headless-e2e`. |

The scripts need Node 24, Docker with `linux/amd64`, cargo, and the Turnkey
`tvc` CLI logged in to the app's organization. Nothing here holds a key longer than
one call. Never commit Turnkey operator files, API keys, or `.env.local`.

## Release

Each deployment has its own Turnkey TVC app, Quorum key, `linux/amd64` image
pinned by `@sha256:`, signed release policy, and wallet descriptors. The
constants of the current app are in
[`apps/privacy-wallet/deploy/release.json`](../apps/privacy-wallet/deploy/release.json).

The `publish-privacy-wallet-image` workflow builds the image of a commit for one
network (`devnet` or `mainnet`, the signed prover policy the image accepts)
into the public GHCR package `imageRepository`, and its run summary has the
reference pinned by digest and the `/tvc_app` SHA-256.
`just image-privacy-wallet <network>` builds the same image locally to compare
against.

```sh
just release private-wallet-devnet-<sha> --image <reference>
node scripts/release.mjs policy private-wallet-devnet-<sha>   # one phase
```

| Phase | What it does |
| --- | --- |
| `build` | Reads the `/tvc_app` SHA-256 from the `--image` reference and records it (`expectedPivotDigest`) with the reference in `privacy-wallet-<release>.deployment.json`. Debug mode stays off; `qosVersion` equals the pinned `qos_core`. |
| `deploy` | Drives the `tvc` CLI: creates the deployment, collects one approval per operator, provisions it, sets it live, and waits until `/v1/info` serves the release. Each approval shows the QOS manifest for the operator to confirm; `--unattended` skips that review. A re-run continues from the last completed step. |
| `policy` | Assembles the release policy from `/v1/info` and `release.json`, signs it with a one-time authority key (`cargo run -p zolana-tvc-protocol --example sign-release-policy`; the private half exists only inside that call), and writes `privacy-wallet-<release>.trust.json`: the policy, the authority public keys, and the QOS identity PCRs a client pins. |
| `pins` | Copies the trust material into tvc-wallet's `src/devnet-release.json`, which it exports as `DEVNET_RELEASE`, and the signed policy and its authorities into tvc-gateway's `configs/`. |

Turnkey keeps three deployable deployments per app. `--prune-deployments`
deletes the oldest that are neither live nor the release's own until the new
one fits. Every Turnkey call goes through the `tvc` CLI and its active login.

The [protocol specification](../crates/protocol/README.md#release-policy)
defines the policy and its signature. Re-signing means a new authority set
every client must accept.

## Wallet descriptors

A wallet descriptor is the operator's grant that lets one client key drive the
enclave operations of one Turnkey wallet. tvc-gateway signs one on each
`POST /v1/private-wallet/enroll`. For a client that talks to the enclave
directly, the client reports the values (`examples/typescript-client` prints
them from `pnpm example examples/enroll.ts`) and the operator signs:

```sh
node scripts/provision-descriptor.mjs --organization-id <org> --wallet-id <id> \
  --address <address> --client-public-key <hex> --out descriptor.json
```

The security domain, environment, and operation list come from the published
trust material (`--trust`, default
`packages/tvc-wallet/src/devnet-release.json`), so the descriptor
names exactly the release the client pins. The provisioning key comes from
`TVC_PROVISIONING_KEY_JSON` or `--provisioning-key <path>`, in the Turnkey API
key file format, and is checked against the public half compiled into the
image before it signs. Treat it as release material. The descriptor itself is
public data; the client stores it at its `TVC_DESCRIPTOR_PATH`.

The script imports the protocol package, so run `pnpm build:ts` first.

## Localnet

`start-localnet.sh PORT_OFFSET SOLANA_KEYPAIR FIXTURE_DIR OUTPUT_ENV` builds
the programs, Photon, the prover, and the CLI from a sibling `../zolana`
checkout, starts a validator with the shielded pool, Photon, and the prover on
the offset ports, mints a test SPL asset, and writes the `SPL_*` values the
client example reads to `OUTPUT_ENV`. `just headless-e2e` runs it. The sibling checkout must
be at the zolana commit
[`headless-local-e2e.yml`](../.github/workflows/headless-local-e2e.yml) pins,
the `gitHead` of the `@heliuslabs/zolana` release the packages depend on.
