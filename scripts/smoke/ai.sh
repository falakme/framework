#!/usr/bin/env bash
# MCP smoke test (T7.12): a stored document carries injected instructions and an agent that
# obeys it works only through the MCP server, as the caller. It cannot read or change outside
# the caller's policy.
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
