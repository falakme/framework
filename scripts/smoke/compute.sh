#!/usr/bin/env bash
# Office Compute smoke test (T7.6): a multi-minute scan, the worker killed mid-job, the job
# finishing once on another worker, and the worker host with no open inbound port.
#
#   scripts/smoke/compute.sh                       # about three minutes
#   SMOKE_JOB_SECONDS=20 scripts/smoke/compute.sh  # a quick run while developing
#
# Set FALAK_BIN, FALAK_OFFICE_BIN and FALAK_WORKER_BIN to use binaries already built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ] || [ -z "${FALAK_OFFICE_BIN:-}" ] || [ -z "${FALAK_WORKER_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli -p falak-office -p falak-worker)
fi
exec python3 "$root/scripts/smoke/compute.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "${FALAK_WORKER_BIN:-$root/target/debug/falak-worker}" \
  "$root/examples/securablock"
