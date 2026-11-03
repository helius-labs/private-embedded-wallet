#!/usr/bin/env bash
# Starts a fresh Zolana localnet (validator, Photon, prover) from the sibling
# zolana checkout and mints one SPL test asset for the client example; see
# `just headless-e2e`.
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: start-localnet.sh PORT_OFFSET SOLANA_KEYPAIR FIXTURE_DIR OUTPUT_ENV" >&2
  exit 2
fi

port_offset="$1"
solana_keypair="$2"
fixture_dir="$3"
output_env="$4"

tvc_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
zolana_root="$tvc_root/../zolana"
rpc_port=$((8899 + port_offset))
photon_port=$((8784 + port_offset))
prover_port=$((3001 + port_offset))
rpc_url="http://127.0.0.1:${rpc_port}"
indexer_url="http://127.0.0.1:${photon_port}"
prover_url="http://127.0.0.1:${prover_port}"

if [[ -e "$fixture_dir" ]]; then
  echo "fixture directory must not already exist: $fixture_dir" >&2
  exit 2
fi
mkdir -p "$fixture_dir"
fixture_dir="$(cd "$fixture_dir" && pwd)"
solana_keypair="$(cd "$(dirname "$solana_keypair")" && pwd)/$(basename "$solana_keypair")"
output_env="$(cd "$(dirname "$output_env")" && pwd)/$(basename "$output_env")"

cd "$zolana_root"
ZOLANA_PORT_OFFSET="$port_offset" just build-programs build-prover-server build-cli ensure-photon

eval "$(cargo run -q -p xtask -- program-ids)"
: "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
: "${USER_REGISTRY_PROGRAM_ID:?xtask did not emit USER_REGISTRY_PROGRAM_ID}"

bin="$zolana_root/target/debug/zolana"
accounts_dir="$fixture_dir/accounts"
export ZOLANA_CONFIG_DIR="$fixture_dir/zolana-config"
export ZOLANA_PHOTON_BIN="$zolana_root/target/debug/photon"
export ZOLANA_PROVER_KEYS_DIR="$zolana_root/prover/server/proving-keys"
mkdir -p "$ZOLANA_CONFIG_DIR"

cargo run -q -p xtask -- generate-account-snapshots \
  --deploy-dir target/deploy --accounts-dir "$accounts_dir"

"$bin" dev start --no-use-surfpool \
  --rpc-port "$rpc_port" --photon-port "$photon_port" --prover-port "$prover_port" \
  --account-dir "$accounts_dir" --limit-ledger-size 5000000 \
  --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
  --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/spr_user_registry.so \
  -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g

"$bin" config set --rpc-url "$rpc_url" --indexer-url "$indexer_url" \
  --prover-url "$prover_url" >/dev/null

"$bin" wallet new --outfile "$fixture_dir/mint-authority.json" >/dev/null
"$bin" wallet new --outfile "$fixture_dir/mint-wallet.json" \
  --funding-keypair "$solana_keypair" >/dev/null
mint_output="$("$bin" dev pool test-mint \
  --keypair "$fixture_dir/mint-wallet.json" \
  --authority-path "$fixture_dir/mint-authority.json" \
  --airdrop-lamports 20000000000 --amount 1000000)"
spl_mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$mint_output")"
spl_asset_id="$(sed -n 's/^ok test_mint .* asset_id=\([^ ]*\).*/\1/p' <<<"$mint_output")"
spl_token_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$mint_output")"
: "${spl_mint:?test-mint did not emit a mint}"
: "${spl_asset_id:?test-mint did not emit an asset id}"
: "${spl_token_account:?test-mint did not emit a token account}"

printf '%s\n' \
  "SPL_MINT=$spl_mint" \
  "SPL_ASSET_ID=$spl_asset_id" \
  "SPL_TOKEN_ACCOUNT=$spl_token_account" >"$output_env"

echo
echo "localnet ready"
echo "  rpc       $rpc_url"
echo "  photon    $indexer_url"
echo "  prover    $prover_url"
echo "  SPL mint  $spl_mint (asset $spl_asset_id)"
