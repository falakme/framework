#!/usr/bin/env bash
# AI readiness smoke test (T7.12): a stored document carries injected instructions and an agent
# that obeys it works only through the MCP projection, as the caller. It cannot read or write
# outside their policy, its writes only queue for approval, it cannot approve its own proposal,
# and fields marked `pii` are not returned to it.
#
#   scripts/smoke/ai.sh
#
# Set FALAK_BIN to use a binary already built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${FALAK_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli)
fi
python3 "$root/scripts/smoke/ai.py" \
  "${FALAK_BIN:-$root/target/debug/falak}" \
  "$root/testdata/apps/clarityai"
