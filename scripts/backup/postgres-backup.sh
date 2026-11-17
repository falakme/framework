#!/usr/bin/env bash
# PostgreSQL Backup Tool for Falak (T3.7).
#
# Dumps the PostgreSQL database into a compressed custom-format archive (-Fc)
# and computes a SHA-256 checksum manifest for tamper detection.
#
# Usage:
#   DATABASE_URL="postgres://user:pass@host:5432/db" BACKUP_DIR="./backups" ./scripts/backup/postgres-backup.sh
#
# Environment variables:
#   DATABASE_URL   - PostgreSQL connection string (required if not using standard PG* vars).
#                    A password in it is moved to PGPASSWORD so it never appears in argv.
#   BACKUP_DIR     - Target directory for backups (default: ./backups)
#   BACKUP_NAME    - Optional backup archive prefix (default: falak_backup_<timestamp>)
#   FALAK_PG_DOCKER - set to 1 to run pg_dump from the postgres:16-alpine image even if pg_dump is
#                     installed (a client newer than the server writes a dump the server cannot read)

set -euo pipefail

# shellcheck source=scripts/backup/_pgurl.sh
. "$(dirname "${BASH_SOURCE[0]}")/_pgurl.sh"
falak_split_url_password

# A dump holds every row: readable by this user only (files 0600, a new directory 0700).
umask 077

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
BACKUP_NAME="${BACKUP_NAME:-falak_backup_${TIMESTAMP}}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" 2>/dev/null || true

ARCHIVE_FILE="${BACKUP_DIR}/${BACKUP_NAME}.dump"
MANIFEST_FILE="${BACKUP_DIR}/${BACKUP_NAME}.sha256"

echo "==> Creating PostgreSQL backup: ${ARCHIVE_FILE}"

if [ "${FALAK_PG_DOCKER:-}" != "1" ] && command -v pg_dump >/dev/null 2>&1; then
  PG_DUMP_CMD=(pg_dump)
elif command -v docker >/dev/null 2>&1; then
  # Fallback to dockerized pg_dump. `-e PGPASSWORD` (name only) passes the value from this
  # environment without putting it in argv; `-e PGPASSWORD=...` would.
  PG_DUMP_CMD=(docker run --rm --network host -i -e PGPASSWORD postgres:16-alpine pg_dump)
else
  echo "Error: Neither 'pg_dump' nor 'docker' is available on PATH." >&2
  exit 1
fi

if [ -n "${DATABASE_URL:-}" ]; then
  "${PG_DUMP_CMD[@]}" --no-owner --no-privileges -Fc -d "$DATABASE_URL" > "$ARCHIVE_FILE"
else
  "${PG_DUMP_CMD[@]}" --no-owner --no-privileges -Fc > "$ARCHIVE_FILE"
fi

# Generate SHA-256 manifest
if command -v shasum >/dev/null 2>&1; then
  (cd "$BACKUP_DIR" && shasum -a 256 "$(basename "$ARCHIVE_FILE")" > "$(basename "$MANIFEST_FILE")")
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "$BACKUP_DIR" && sha256sum "$(basename "$ARCHIVE_FILE")" > "$(basename "$MANIFEST_FILE")")
else
  echo "Warning: Neither shasum nor sha256sum available to generate manifest." >&2
fi

BACKUP_BYTES="$(wc -c < "$ARCHIVE_FILE" | tr -d ' ')"
echo "==> Backup complete: ${ARCHIVE_FILE} (${BACKUP_BYTES} bytes)"
echo "==> Manifest: ${MANIFEST_FILE}"
