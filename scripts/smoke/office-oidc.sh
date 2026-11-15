#!/usr/bin/env bash
# Sign-in through a real OpenID Connect provider (ADR-0011).
#
# The provider is Dex, an independent open-source OIDC server, run in a container: its
# discovery document, its RS256 keys and its ID tokens are not ours. Office is started
# with FALAK_OIDC_ISSUER pointing at it, a person signs in at Dex, and the ID token is
# traded at Office for an Office session.
#
#   scripts/smoke/office-oidc.sh
#
# Needs Docker. Set FALAK_OFFICE_BIN to use a binary that is already built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
name="falak-smoke-dex-$$"
office_pid=""
cleanup() {
  [ -n "$office_pid" ] && kill "$office_pid" 2>/dev/null || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

if [ -z "${FALAK_OFFICE_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p falak-office)
  FALAK_OFFICE_BIN="$root/target/debug/falak-office"
fi

free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
dex_port="$(free_port)"
office_port="$(free_port)"
issuer="http://127.0.0.1:$dex_port/dex"

# `password` for dana@example.com, as a bcrypt hash.
cat >"$work/dex.yaml" <<YAML
issuer: $issuer
storage: { type: memory }
web: { http: 0.0.0.0:5556 }
oauth2: { passwordConnector: local, skipApprovalScreen: true }
enablePasswordDB: true
staticPasswords:
  - email: dana@example.com
    hash: "\$2a\$10\$bd.t8UuBXMMG12h8SLaKku2enQkAi3AFlJOscl./r7XuLXJCMmYDq"
    username: dana
    userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
staticClients:
  - id: falak-office
    name: Falak Office
    secret: not-a-secret
    redirectURIs: ["http://127.0.0.1/callback"]
YAML

docker run -d --name "$name" -p "127.0.0.1:$dex_port:5556" -v "$work/dex.yaml:/etc/dex/config.yaml:ro" \
  ghcr.io/dexidp/dex:v2.45.1 dex serve /etc/dex/config.yaml >/dev/null
for _ in $(seq 1 60); do
  curl -fsS "$issuer/.well-known/openid-configuration" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$issuer/.well-known/openid-configuration" >/dev/null || { docker logs "$name" >&2; echo "Dex did not start" >&2; exit 1; }

FALAK_OIDC_ISSUER="$issuer" FALAK_OIDC_AUDIENCE=falak-office FALAK_OIDC_AUTO_CREATE=example.com \
  "$FALAK_OFFICE_BIN" serve --port "$office_port" --data "$work/office" >"$work/office.log" 2>&1 &
office_pid=$!
for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$office_port/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done

python3 "$root/scripts/smoke/office-oidc.py" "$issuer" "http://127.0.0.1:$office_port"
