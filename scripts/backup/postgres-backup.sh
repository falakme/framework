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
#   DATABASE_URL   - PostgreSQL connection string (required if not using standard PG* vars)
#   BACKUP_DIR     - Target directory for backups (default: ./backups)
#   BACKUP_NAME    - Optional backup archive prefix (default: falak_backup_<timestamp>)

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
BACKUP_NAME="${BACKUP_NAME:-falak_backup_${TIMESTAMP}}"

mkdir -p "$BACKUP_DIR"

ARCHIVE_FILE="${BACKUP_DIR}/${BACKUP_NAME}.dump"
MANIFEST_FILE="${BACKUP_DIR}/${BACKUP_NAME}.sha256"

echo "==> Creating PostgreSQL backup: ${ARCHIVE_FILE}"

if command -v pg_dump >/dev/null 2>&1; then
  PG_DUMP_CMD="pg_dump"
elif command -v docker >/dev/null 2>&1; then
  # Fallback to dockerized pg_dump
  PG_DUMP_CMD="docker run --rm --network host -i postgres:16-alpine pg_dump"
else
  echo "Error: Neither 'pg_dump' nor 'docker' is available on PATH." >&2
  exit 1
fi

if [ -n "${DATABASE_URL:-}" ]; then
  $PG_DUMP_CMD --no-owner --no-privileges -Fc -d "$DATABASE_URL" > "$ARCHIVE_FILE"
else
  $PG_DUMP_CMD --no-owner --no-privileges -Fc > "$ARCHIVE_FILE"
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
