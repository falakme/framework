#!/usr/bin/env bash
# Run the Notebook smoke test on SQLite, PostgreSQL and Workers (T2.11).
#
#   DATABASE_URL=postgres://... FALAK_URL=https://... scripts/smoke/all-targets.sh
#
# A target whose setting is missing fails the run. It is never skipped quietly.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
status=0
for target in sqlite postgres workers; do
  echo "=== $target ==="
  if FALAK_TARGET="$target" bash "$here/notebook.sh"; then
    echo "--- $target: passed"
  else
    echo "--- $target: FAILED"
    status=1
  fi
done
exit $status
