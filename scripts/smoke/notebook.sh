#!/usr/bin/env bash
# Notebook smoke test (T1.17).
#
# Builds the CLI, serves a copy of examples/notebook on a free port, runs the checks in
# notebook.py against it, and stops the server. Exit code 0 means every check passed.
#
#   scripts/smoke/notebook.sh
#
# Set FALAK_BIN to use an already built binary.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

if [ -z "${FALAK_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli)
  FALAK_BIN="$root/target/debug/falak"
fi

cp -R "$root/examples/notebook" "$work/app"
rm -rf "$work/app/web" "$work/app/.falak"

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
"$FALAK_BIN" serve "$work/app" --port "$port" >"$work/server.log" 2>&1 &
server_pid=$!

# Wait up to 30 seconds for the server to answer.
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "the server stopped early:" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.5
done

if ! python3 "$root/scripts/smoke/notebook.py" "http://127.0.0.1:$port"; then
  echo "--- server log ---" >&2
  cat "$work/server.log" >&2
  exit 1
fi
