#!/usr/bin/env bash
# AI readiness smoke test (T7.12): a document with injected instructions is scanned for
# personal data on a worker and then handed to an agent that obeys it. The agent works only
# through the MCP projection, as the caller, and cannot read or write outside their policy.
#
#   scripts/smoke/ai.sh
#
# Also runs the PII shield page's tests when Node is installed.
# Set FALAK_BIN, FALAK_OFFICE_BIN and FALAK_WORKER_BIN to use binaries already built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ] || [ -z "${FALAK_OFFICE_BIN:-}" ] || [ -z "${FALAK_WORKER_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli -p falak-office -p falak-worker)
fi
python3 "$root/scripts/smoke/ai.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "${FALAK_OFFICE_BIN:-$root/target/debug/falak-office}" \
  "${FALAK_WORKER_BIN:-$root/target/debug/falak-worker}" \
  "$root/examples/clarityai"
if command -v node >/dev/null 2>&1; then
  echo
  echo "PII shield page:"
  node --test "$root/examples/clarityai/shield/shield.test.mjs" 2>&1 | grep -E "^(✔|✖|ℹ (pass|fail))" || true
else
  echo "(skipping the PII shield page tests: Node is not installed)"
fi
