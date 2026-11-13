set dotenv-load

pnpm := "npx --yes pnpm@9.15.0"

default:
    @just --list

fmt:
    cargo fmt --all
    cargo fmt --manifest-path apps/tvc-gateway/Cargo.toml --all

fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path apps/tvc-gateway/Cargo.toml --all -- --check

check:
    cargo check --workspace --all-targets --all-features --locked
    cargo check --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo clippy --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked -- -D warnings

test:
    cargo test --workspace --all-targets --all-features --locked
    cargo test --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked

regenerate-protocol-fixtures:
    cargo test --test conformance regenerate_content_addressed_fixtures -- --ignored --exact

check-protocol-fixtures:
    #!/usr/bin/env sh
    set -eu
    fixture_status="$(git status --porcelain --untracked-files=all -- crates/protocol/fixtures)"
    if [ -n "$fixture_status" ]; then
        echo "protocol fixtures differ from the committed conformance corpus" >&2
        echo "$fixture_status" >&2
        exit 1
    fi

setup: install-ts

install-ts:
    {{pnpm}} install --frozen-lockfile

lint-ts:
    {{pnpm}} lint:ts

typecheck-ts:
    {{pnpm}} typecheck:ts

test-ts:
    {{pnpm}} test:ts

build-ts:
    {{pnpm}} build:ts

ci-ts:
    {{pnpm}} ci:ts

# Fresh Zolana localnet plus the Rust testkits, then the client example's SOL and SPL lifecycles and a transfer to an unregistered address; needs a sibling ../zolana checkout.
headless-e2e port_offset="200":
    #!/usr/bin/env bash
    set -euo pipefail
    run_dir="$(mktemp -d)"
    wallet_keypair="${TVC_SOLANA_KEYPAIR_PATH:-$run_dir/wallet.json}"
    fixture_env="$run_dir/fixture.env"
    fixture_dir="$run_dir/fixture"
    if [ -z "${TVC_SOLANA_KEYPAIR_PATH:-}" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile "$wallet_keypair"
    else
        test -f "$wallet_keypair" || { echo "missing TVC_SOLANA_KEYPAIR_PATH: $wallet_keypair" >&2; exit 1; }
    fi
    rpc_port=$((8899 + {{port_offset}}))
    photon_port=$((8784 + {{port_offset}}))
    prover_port=$((3001 + {{port_offset}}))
    rpc_url="http://127.0.0.1:${rpc_port}"
    indexer_url="http://127.0.0.1:${photon_port}"
    prover_url="http://127.0.0.1:${prover_port}"
    server_pid=""
    service_pid=""
    cleanup() {
        for pid in $server_pid $service_pid; do kill "$pid" 2>/dev/null || true; done
        for port in "$rpc_port" "$photon_port" "$prover_port"; do
            lsof -ti "tcp:${port}" 2>/dev/null | xargs kill 2>/dev/null || true
        done
        rm -rf -- "$run_dir"
    }
    trap cleanup EXIT
    {{pnpm}} install --frozen-lockfile
    {{pnpm}} build:ts
    bash scripts/start-localnet.sh "{{port_offset}}" "$wallet_keypair" "$fixture_dir" "$fixture_env"
    source "$fixture_env"
    solana airdrop 10 "$(solana address --keypair "$wallet_keypair")" --url "$rpc_url" >/dev/null
    healthy() {
        for _ in $(seq 1 120); do
            if curl --fail --silent "http://127.0.0.1:$1/health" >/dev/null; then return; fi
            if ! kill -0 "$2" 2>/dev/null; then wait "$2"; fi
            sleep 1
        done
        curl --fail --silent "http://127.0.0.1:$1/health" >/dev/null
    }
    cargo run -p zolana-tvc-privacy-wallet --features local-dev --bin zolana-tvc-privacy-wallet-local -- \
        --wallet-keypair "$wallet_keypair" --prover-url "$prover_url" &
    server_pid=$!
    healthy 44020 "$server_pid"
    cargo run -p spr-tvc-decryption-service --features local-dev --bin spr-tvc-decryption-service-local &
    service_pid=$!
    healthy 44030 "$service_pid"
    export TVC_LOCAL_TESTKIT_ENDPOINT="http://127.0.0.1:44020"
    export DECRYPTION_SERVICE_LOCAL_ENDPOINT="http://127.0.0.1:44030"
    export TVC_LOCAL_PROVER_URL="http://127.0.0.1:44021"
    export TVC_SOLANA_KEYPAIR_PATH="$wallet_keypair" TVC_WALLET_PATH="$run_dir/wallet.tvc.json"
    export ZOLANA_ENDPOINT="$rpc_url" ZOLANA_INDEXER_URL="$indexer_url" ZOLANA_PROVER_URL="$prover_url"
    export SPL_MINT SPL_ASSET_ID SPL_TOKEN_ACCOUNT
    for example in deposit_transfer_withdraw spl_deposit_transfer_withdraw unregistered_recipient; do
        {{pnpm}} --filter zolana-tvc-typescript-client-example example "examples/$example.ts"
    done

ci: fmt-check lint test check-protocol-fixtures install-ts ci-ts

# One enclave application's image for a network: privacy-wallet or decryption-service.
image app="privacy-wallet" network="devnet":
    docker build --platform linux/amd64 --provenance=false --build-arg SPR_NETWORK={{network}} \
        --build-arg APP_PACKAGE="$(jq -r .package apps/{{app}}/deploy/release.json)" -f apps/enclave.Dockerfile .

image-tvc-gateway:
    docker build --platform linux/amd64 -f apps/tvc-gateway/Dockerfile .

# The gateway on loopback against the local testkit enclave and a mock Turnkey; see apps/tvc-gateway/README.md.
gateway-e2e: install-ts
    {{pnpm}} build:ts
    {{pnpm}} --filter @zolana/tvc-gateway-e2e e2e

# Deploy a network's published image, sign its release policy and pin it in tvc-wallet; see scripts/release.mjs.
release network release_id *flags:
    node scripts/release.mjs all {{release_id}} --network {{network}} {{flags}}

