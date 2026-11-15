#!/usr/bin/env bash
# Notebook smoke test (T1.17).
#
# Builds the CLI, serves a copy of examples/notebook on a free port, runs the checks in
# notebook.py against it, then runs the generated TypeScript client against the same
# server (if Node and pnpm are installed), and stops the server. Exit code 0 means every
# check passed.
#
#   scripts/smoke/notebook.sh
#
# Set FALAK_BIN to use an already built binary.
#
# Targets (T2.11). The same checks run on each, with no change to examples/notebook/:
#
#   FALAK_TARGET=sqlite   (default) serve here on SQLite
#   FALAK_TARGET=postgres serve here on the PostgreSQL named by DATABASE_URL
#   FALAK_TARGET=workers  check the deployed app at FALAK_URL (after `falak deploy`)
#
#   DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/notebook \
#     FALAK_TARGET=postgres scripts/smoke/notebook.sh
#   FALAK_TARGET=workers FALAK_URL=https://notebook.example.workers.dev scripts/smoke/notebook.sh
#
# `scripts/smoke/all-targets.sh` runs all three.
set -euo pipefail

target="${FALAK_TARGET:-sqlite}"
case "$target" in
  sqlite) ;;
  postgres)
    [ -n "${DATABASE_URL:-}" ] || { echo "FALAK_TARGET=postgres needs DATABASE_URL" >&2; exit 2; }
    ;;
  workers)
    [ -n "${FALAK_URL:-}" ] || { echo "FALAK_TARGET=workers needs FALAK_URL" >&2; exit 2; }
    ;;
  *) echo "unknown FALAK_TARGET '$target' (sqlite, postgres or workers)" >&2; exit 2 ;;
esac
echo "target: $target"

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

if [ "$target" = workers ]; then
  python3 "$root/scripts/smoke/notebook.py" "$FALAK_URL"
  exit $?
fi

if [ -z "${FALAK_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli)
  FALAK_BIN="$root/target/debug/falak"
fi

cp -R "$root/examples/notebook" "$work/app"
rm -rf "$work/app/web" "$work/app/.falak"

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
if [ "$target" = sqlite ]; then
  # An inherited DATABASE_URL must not turn this into a PostgreSQL run.
  env -u DATABASE_URL "$FALAK_BIN" serve "$work/app" --port "$port" >"$work/server.log" 2>&1 &
else
  "$FALAK_BIN" serve "$work/app" --port "$port" >"$work/server.log" 2>&1 &
fi
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

fail() {
  echo "--- server log ---" >&2
  cat "$work/server.log" >&2
  exit 1
}

python3 "$root/scripts/smoke/notebook.py" "http://127.0.0.1:$port" || fail

if [ -d "$root/node_modules" ] && command -v pnpm >/dev/null 2>&1; then
  echo
  echo "generated TypeScript client:"
  (cd "$root/examples/notebook/web" && FALAK_URL="http://127.0.0.1:$port" pnpm --silent test) || fail
else
  echo "(skipping the TypeScript client check: run 'pnpm install' first)"
fi
