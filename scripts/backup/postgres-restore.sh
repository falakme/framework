#!/usr/bin/env bash
# PostgreSQL Restore Tool for Falak (T3.7).
#
# Verifies archive SHA-256 integrity and restores into a target database.
#
# Usage:
#   DATABASE_URL="postgres://user:pass@host:5432/db" ./scripts/backup/postgres-restore.sh <path_to_dump>
#
# Arguments:
#   $1 - Path to the backup archive file (.dump)
#
# Environment variables:
#   DATABASE_URL - Target PostgreSQL database URL (required)
#   SKIP_CHECKSUM - Set to 1 to skip checksum verification (default: 0)

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <path_to_backup.dump>" >&2
  exit 1
fi

ARCHIVE_FILE="$1"
if [ ! -f "$ARCHIVE_FILE" ]; then
  echo "Error: Backup archive not found: $ARCHIVE_FILE" >&2
  exit 1
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "Error: DATABASE_URL environment variable must be set." >&2
  exit 1
fi

MANIFEST_FILE="${ARCHIVE_FILE%.dump}.sha256"

# Checksum verification
if [ "${SKIP_CHECKSUM:-0}" != "1" ] && [ ! -f "$MANIFEST_FILE" ]; then
  echo "Warning: no checksum manifest ($MANIFEST_FILE); the archive's integrity is not verified." >&2
elif [ "${SKIP_CHECKSUM:-0}" != "1" ]; then
  echo "==> Verifying SHA-256 checksum..."
  ARCHIVE_DIR="$(cd "$(dirname "$ARCHIVE_FILE")" && pwd)"
  ARCHIVE_BASE="$(basename "$ARCHIVE_FILE")"
  MANIFEST_BASE="$(basename "$MANIFEST_FILE")"

  if command -v shasum >/dev/null 2>&1; then
    (cd "$ARCHIVE_DIR" && shasum -a 256 -c "$MANIFEST_BASE")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$ARCHIVE_DIR" && sha256sum -c "$MANIFEST_BASE")
  else
    echo "Error: no shasum or sha256sum to verify the archive; set SKIP_CHECKSUM=1 to restore anyway." >&2
    exit 1
  fi
  echo "==> Checksum verified OK."
fi

echo "==> Restoring from ${ARCHIVE_FILE} into target database..."

if [ "${FALAK_PG_DOCKER:-}" != "1" ] && command -v pg_restore >/dev/null 2>&1; then
  PG_RESTORE_CMD="pg_restore"
elif command -v docker >/dev/null 2>&1; then
  PG_RESTORE_CMD="docker run --rm --network host -i postgres:16-alpine pg_restore"
else
  echo "Error: Neither 'pg_restore' nor 'docker' is available on PATH." >&2
  exit 1
fi

# Restore options:
# -Fc archive format
# --clean: drop database objects before recreating them
# --if-exists: avoid errors on missing objects during clean
# --no-owner --no-privileges: ignore original database role owners and permissions
# A failure is a failure: do not report a finished restore that was not.
if ! $PG_RESTORE_CMD --clean --if-exists --no-owner --no-privileges -d "$DATABASE_URL" < "$ARCHIVE_FILE"; then
  echo "Error: pg_restore reported errors; the target database may be incomplete." >&2
  exit 1
fi

echo "==> Restore operation finished."
