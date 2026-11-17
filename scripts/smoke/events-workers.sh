#!/usr/bin/env bash
# Durable events on Workers + D1 (T5.7, edge half). Needs wrangler login or
# CLOUDFLARE_API_TOKEN, `worker-build`, and npx (cloudflared). Deletes what it creates.
#
#   scripts/smoke/events-workers.sh [account id]
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ] || [ -z "${FALAK_OFFICE_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli -p falak-office)
fi
exec python3 "$root/scripts/smoke/events-workers.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "$root/testdata/apps/gardenx" \
  "${1:-${CLOUDFLARE_ACCOUNT_ID:-cc0e1d4c6b2d2777745f5b92c2c654c3}}"
