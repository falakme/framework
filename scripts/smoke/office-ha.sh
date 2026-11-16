#!/usr/bin/env bash
# Office high availability smoke (T6.2): two instances, one database, kill one.
#
#   scripts/smoke/office-ha.sh
#   OFFICE_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55433/office scripts/smoke/office-ha.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_OFFICE_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-office)
fi
exec python3 "$root/scripts/smoke/office-ha.py" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "${OFFICE_DATABASE_URL:-}"
