#!/usr/bin/env bash
# Build the edge runtime for Workers with a tiny app inside, and fail if the gzipped
# WASM is over the budget (T2.8).
#
#   scripts/check-wasm-size.sh
#
# The budget is a tripwire against surprise growth, not a target. Workers accepts 3 MiB
# gzipped on the free plan and 10 MiB on a paid plan. Raise it on purpose, in a commit
# that says why.
set -euo pipefail

BUDGET_GZIP_KIB="${BUDGET_GZIP_KIB:-800}"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

cargo build --locked -q -p falak-cli
./target/debug/falak build examples/notebook >/dev/null

if ! command -v worker-build >/dev/null 2>&1; then
  cargo install worker-build --locked
fi

(cd crates/falak-runtime-edge &&
  FALAK_IR_FILE="$root/examples/notebook/.falak/ir.json" worker-build --release >/dev/null)

wasm="crates/falak-runtime-edge/build/index_bg.wasm"
raw=$(($(wc -c <"$wasm")))
gz=$(($(gzip -9 -c "$wasm" | wc -c)))
echo "edge runtime wasm: $((raw / 1024)) KiB raw, $((gz / 1024)) KiB gzip (budget $BUDGET_GZIP_KIB KiB gzip)"

if [ "$((gz / 1024))" -gt "$BUDGET_GZIP_KIB" ]; then
  echo "over budget" >&2
  exit 1
fi
