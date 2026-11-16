#!/usr/bin/env bash
# Take a physical base backup of a whole PostgreSQL cluster (every database in it), for
# point-in-time recovery together with the continuously archived WAL (T6.3).
#
#   PGHOST=... PGUSER=... PGPASSWORD=... ./scripts/backup/pitr-base.sh /backups/base-2026-11-16
#
# The directory must not exist or must be empty. The result is verified with
# `pg_verifybackup` (checksums of every file against the backup manifest), and a SHA-256 of
# the manifest is written beside it (`<dir>.manifest.sha256`), so a restore can tell the base backup was not altered.
set -euo pipefail

out="${1:?usage: pitr-base.sh <empty target directory>}"
if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
  echo "error: $out is not empty" >&2
  exit 1
fi

# -X stream: the WAL needed to make this backup consistent travels with it.
# -c fast: do not wait for the next scheduled checkpoint.
pg_basebackup -D "$out" -Fp -X stream -c fast --manifest-checksums=SHA256 -P

pg_verifybackup "$out"
# Next to the backup, not inside it: pg_verifybackup rejects files it does not know.
( sha256sum "$out/backup_manifest" 2>/dev/null || shasum -a 256 "$out/backup_manifest" ) |
  cut -d' ' -f1 >"${out%/}.manifest.sha256"
echo "base backup written and verified: $out"
