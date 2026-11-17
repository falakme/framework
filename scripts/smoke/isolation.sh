#!/usr/bin/env bash
# Isolation smoke test (T3.15): Falak.me, two workspaces, everything A tries on B fails.
#
# Targets, as for notebook.sh:
#
#   FALAK_TARGET=sqlite   (default) serve here on SQLite
#   FALAK_TARGET=postgres serve here on the PostgreSQL named by DATABASE_URL
#   FALAK_TARGET=workers  check the deployed app at FALAK_URL (after `falak deploy`)
#
# It also runs the object storage tests, which include a tenant asking for another
# tenant's file. With FALAK_S3_ENDPOINT, FALAK_S3_BUCKET, FALAK_S3_ACCESS_KEY and
# FALAK_S3_SECRET_KEY set (S3, R2, MinIO) it also runs files.py over HTTP against that store. Set FALAK_BIN to use an already built binary.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

target="${FALAK_TARGET:-sqlite}"
case "$target" in
  sqlite) ;;
  postgres) [ -n "${DATABASE_URL:-}" ] || { echo "FALAK_TARGET=postgres needs DATABASE_URL" >&2; exit 2; } ;;
  workers) [ -n "${FALAK_URL:-}" ] || { echo "FALAK_TARGET=workers needs FALAK_URL" >&2; exit 2; } ;;
  *) echo "unknown FALAK_TARGET '$target' (sqlite, postgres or workers)" >&2; exit 2 ;;
esac
echo "target: $target"

(cd "$root" && cargo test --locked -q -p falak-storage 2>&1 | tail -3)

if [ "$target" = workers ]; then
  python3 "$root/scripts/smoke/isolation.py" "$FALAK_URL"
  exit $?
fi

if [ -z "${FALAK_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-cli)
  FALAK_BIN="$root/target/debug/falak"
fi

cp -R "$root/testdata/apps/falakme" "$work/app"
rm -rf "$work/app/.falak"

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
if [ "$target" = sqlite ]; then
  env -u DATABASE_URL "$FALAK_BIN" serve "$work/app" --port "$port" >"$work/server.log" 2>&1 &
else
  "$FALAK_BIN" serve "$work/app" --port "$port" >"$work/server.log" 2>&1 &
fi
server_pid=$!

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

if [ -n "${FALAK_S3_ENDPOINT:-}" ]; then
  python3 "$root/scripts/smoke/files.py" "http://127.0.0.1:$port" || {
    echo "--- server log ---" >&2
    cat "$work/server.log" >&2
    exit 1
  }
fi

python3 "$root/scripts/smoke/isolation.py" "http://127.0.0.1:$port" || {
  echo "--- server log ---" >&2
  cat "$work/server.log" >&2
  exit 1
}
