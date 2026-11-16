#!/usr/bin/env bash
# Disaster-recovery drill (T6.8): destroy the databases, restore them to a point in time,
# rotate a compromised app credential, and report the time taken and the data lost.
# Fails if either is over the objectives (RPO 5 minutes, RTO 1 hour).
#
#   scripts/smoke/dr.sh
#
# Needs Docker with the postgres:16-alpine image (set DR_PG_IMAGE to use another).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ] || [ -z "${FALAK_OFFICE_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli -p falak-office)
fi
exec python3 "$root/scripts/smoke/dr.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "$root/examples/notebook"
