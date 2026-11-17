#!/usr/bin/env bash
# Durable events smoke test (T5.7): place orders while Office and a consumer are killed,
# then check that orders and inventory agree exactly.
#
#   scripts/smoke/events.sh
#   OFFICE_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55433/office scripts/smoke/events.sh
#
# Set FALAK_BIN and FALAK_OFFICE_BIN to use binaries that are already built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ] || [ -z "${FALAK_OFFICE_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli -p falak-office)
fi
exec python3 "$root/scripts/smoke/events.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "$root/testdata/apps/gardenx" \
  "${OFFICE_DATABASE_URL:-}"
