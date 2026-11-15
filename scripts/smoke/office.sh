#!/usr/bin/env bash
# Falak Office smoke test (T4.13): real processes, sign in once, rotation under load,
# and each trust tier with Office stopped.
#
#   scripts/smoke/office.sh
#   OFFICE_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55433/office scripts/smoke/office.sh
#
# Set FALAK_BIN and FALAK_OFFICE_BIN to use binaries that are already built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ] || [ -z "${FALAK_OFFICE_BIN:-}" ] || [ -z "${FALAK_STUDIO_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli -p falak-office -p falak-studio)
fi
exec python3 "$root/scripts/smoke/office.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "$root/examples/notebook" \
  "${FALAK_STUDIO_BIN:-$root/target/debug/falak-studio}" \
  "${OFFICE_DATABASE_URL:-}"
