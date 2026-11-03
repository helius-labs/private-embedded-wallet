# Privacy wallet Next.js demo

The ordinary Helius embedded-wallet demo with one additional **Private** tab.
The tab connects the signed-in Turnkey HD wallet to an independently verified
TVC release and supports:

- automatic descriptor enrollment and deterministic shielded identity setup;
- devnet wallet registration, paid from the wallet's devnet SOL (fund it with
  at least 0.01 SOL first);
- public and private balances for SOL and registered classic SPL assets, the
  private ones decrypted by the enclave and verified against the private index;
- shielding SOL or classic SPL into the private balance;
- private SOL/SPL transfers;
- automatic UTXO consolidation when a spend needs more inputs than one proof
  takes;
- unshielding SOL/SPL, creating the public associated token account
  idempotently when needed.

`providers.tsx` mounts `HeliusPrivateWalletProvider` from
[`@zolana/tvc-wallet-kit`](../../packages/tvc-wallet-kit), and
`use-private-wallet-flow.ts` drives everything through
`useHeliusWallet().private`: `connect()` when the wallet signs in, then the
session's `register`, `shield`, `transfer`, `unshield`, `sync`, `holdings` and
`history`.

The package owns the non-exportable browser credential, pinned deployment
verification, descriptor enrollment, exact owner-approved bootstrap, stable
identity checks, descriptor/sealed-seed persistence, Turnkey signing of the
SDK's transactions, and the sync-at-landed-slot rule. The example resyncs
after reload.

The release comes from tvc-wallet's `DEVNET_RELEASE`, the
`zolana-private-wallet-devnet` app in the Helius TVC organization. The demo
talks to devnet-e's indexer and prover, and the enclave seals each proof's
witness to a prover devnet's signed policy admits.
This demo is for disposable devnet funds only.

## Run

Create `.env.local` from `.env.example` and fill:

- `NEXT_PUBLIC_HELIUS_API_KEY` and `HELIUS_API_KEY`: a Helius API key of the
  project the embedded wallets belong to. The route handler sends the server
  key to tvc-gateway, which resolves the project from it and checks each
  wallet's Turnkey sub-org against that project.

Then run from the zolana-tvc root:

```sh
npx --yes pnpm@9.15.0 install
npx --yes pnpm@9.15.0 build:ts
npx --yes pnpm@9.15.0 --filter zolana-privacy-wallet-next-app dev
```

Open <http://localhost:3002>.

The gateway, indexer, and prover deployment is selected inside tvc-wallet-kit
(`TVC_GATEWAY_URL` overrides the gateway for operators); applications do not
pass endpoints or release identifiers to the provider or hook.

## AWS demo

The shared devnet demo is deployed at
<https://i6npwfd4mh.eu-west-1.awsapprunner.com>.

The deployment uses a private ECR repository and an App Runner service managed
by the `zolana-privacy-wallet-demo` CloudFormation stack. With an active AWS
profile and a populated `.env.local`, deploy from the zolana-tvc root:

```sh
AWS_PROFILE=<profile> examples/privacy-wallet-next-app/deploy/aws/deploy.sh
```

The image is built for `linux/amd64`. The Helius browser key is supplied as a
BuildKit secret, and the server key as an App Runner runtime environment
variable.

## Verification

```sh
npx --yes pnpm@9.15.0 --filter zolana-privacy-wallet-next-app test
npx --yes pnpm@9.15.0 --filter zolana-privacy-wallet-next-app typecheck
npx --yes pnpm@9.15.0 --filter zolana-privacy-wallet-next-app build
```

The app mounts the package handler at `/api/tvc` and uses no example-local
enrollment client.

Never commit `.env.local`, Turnkey API private keys, operator files, or sealed
wallet state.
