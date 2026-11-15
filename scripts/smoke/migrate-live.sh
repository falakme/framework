#!/usr/bin/env bash
# A schema change applied with `falak migrate` while the app is running and being used
# (Phase 3 gate). Needs a PostgreSQL URL:
#
#   DATABASE_URL=postgres://... scripts/smoke/migrate-live.sh
#
# Version 1 of Falak.me serves traffic. A second version adds an optional column to
# `page`; `falak migrate plan` shows it and `falak migrate apply` runs it against the same
# database while a client keeps calling the running server. Every call must succeed. The
# new column must then exist, and version 2 must serve it.
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL to a PostgreSQL database that falak may use}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
v1_pid=""
v2_pid=""
traffic_pid=""
cleanup() {
  for p in "$traffic_pid" "$v1_pid" "$v2_pid"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

if [ -z "${FALAK_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli)
  FALAK_BIN="$root/target/debug/falak"
fi

cp -R "$root/examples/falakme" "$work/v1"
rm -rf "$work/v1/.falak"
cp -R "$work/v1" "$work/v2"
# Version 2: one more optional field on `page`.
python3 - "$work/v2/entities/page.yaml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("  owner_id:", "  subtitle: { type: text, max_length: 200 }\n  owner_id:", 1)
open(p, "w").write(s)
PY

port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
wait_up() {
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$1/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "the server did not start" >&2
  return 1
}

p1="$(port)"
"$FALAK_BIN" serve "$work/v1" --port "$p1" >"$work/v1.log" 2>&1 &
v1_pid=$!
wait_up "$p1"

echo "--- plan for version 2"
"$FALAK_BIN" migrate plan "$work/v2" --driver postgres

# Traffic against the running version 1 while the migration runs.
python3 "$root/scripts/smoke/traffic.py" "http://127.0.0.1:$p1" "$work/traffic.json" &
traffic_pid=$!
sleep 3

echo "--- apply"
"$FALAK_BIN" migrate apply "$work/v2" --driver postgres
sleep 3
touch "$work/stop"
wait "$traffic_pid" || { echo "traffic failed" >&2; cat "$work/traffic.json" >&2 || true; exit 1; }
traffic_pid=""
cat "$work/traffic.json"
python3 - "$work/traffic.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert r["requests"] > 50, f"too few requests to mean anything: {r}"
assert r["failures"] == 0, f"requests failed during the migration: {r}"
print(f"no downtime: {r['requests']} requests, 0 failures, slowest {r['slowest_ms']} ms")
PY

echo "--- version 2 serves the new column"
p2="$(port)"
"$FALAK_BIN" serve "$work/v2" --port "$p2" >"$work/v2.log" 2>&1 &
v2_pid=$!
wait_up "$p2"
python3 "$root/scripts/smoke/subtitle.py" "http://127.0.0.1:$p2"
