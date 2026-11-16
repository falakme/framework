#!/usr/bin/env bash
# Restore a whole PostgreSQL cluster (every database in it) to a point in time (T6.3).
#
#   ./scripts/backup/pitr-restore.sh \
#     --base /backups/base-2026-11-16 \
#     --archive /wal-archive \
#     --data /var/lib/postgresql/restore \
#     --target-time '2026-11-16 14:03:00+00'
#
# --target-time is the last moment to keep: the recovery stops just after it, so choose a
# time before the damage (a bad migration, a dropped table or database). Without it the
# recovery replays every archived WAL file (the latest state the archive holds).
#
# This prepares the data directory and writes the recovery settings; PostgreSQL does the
# replay when it starts on that directory. Pass --start (and --port) to start it with
# pg_ctl and wait until recovery has finished and the server accepts writes.
#
# It never writes into the base backup or the archive, and refuses a data directory that
# is not empty, so it cannot overwrite a live database.
set -euo pipefail

base="" archive="" data="" target="" start=0 port=5432
while [ $# -gt 0 ]; do
  case "$1" in
  --base) base="$2"; shift 2 ;;
  --archive) archive="$2"; shift 2 ;;
  --data) data="$2"; shift 2 ;;
  --target-time) target="$2"; shift 2 ;;
  --start) start=1; shift ;;
  --port) port="$2"; shift 2 ;;
  *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ -n "$base" ] && [ -n "$archive" ] && [ -n "$data" ] || {
  echo "usage: pitr-restore.sh --base DIR --archive DIR --data DIR [--target-time TS] [--start] [--port N]" >&2
  exit 2
}
[ -f "$base/PG_VERSION" ] && [ -f "$base/backup_manifest" ] || {
  echo "error: $base is not a base backup made by pitr-base.sh" >&2
  exit 1
}
[ -d "$archive" ] || { echo "error: no WAL archive at $archive" >&2; exit 1; }
if [ -e "$data" ] && [ -n "$(ls -A "$data" 2>/dev/null)" ]; then
  echo "error: $data is not empty; restore into a new directory" >&2
  exit 1
fi

# Tamper check on the base backup before anything is copied.
if [ -f "${base%/}.manifest.sha256" ]; then
  want="$(cat "${base%/}.manifest.sha256")"
  got="$( (sha256sum "$base/backup_manifest" 2>/dev/null || shasum -a 256 "$base/backup_manifest") | cut -d' ' -f1)"
  [ "$want" = "$got" ] || { echo "error: the base backup's manifest was altered" >&2; exit 1; }
fi
pg_verifybackup "$base" >/dev/null

mkdir -p "$data"
cp -a "$base/." "$data/"
chmod 700 "$data"
rm -f "$data/backup_manifest" "$data/postmaster.pid"

{
  echo "# written by pitr-restore.sh"
  echo "restore_command = 'cp \"$archive/%f\" \"%p\"'"
  [ -n "$target" ] && echo "recovery_target_time = '$target'"
  echo "recovery_target_action = 'promote'"
  echo "archive_mode = off"
} >>"$data/postgresql.auto.conf"
touch "$data/recovery.signal"
echo "restore prepared in $data${target:+ (stops at $target)}"

if [ "$start" = 1 ]; then
  pg_ctl -D "$data" -o "-p $port -c listen_addresses=127.0.0.1" -l "$data/restore.log" -w start
  # Recovery is over when the server stops being a standby.
  for _ in $(seq 1 600); do
    if [ "$(psql -h 127.0.0.1 -p "$port" -U "${PGUSER:-postgres}" -d postgres -Atc 'select pg_is_in_recovery()' 2>/dev/null)" = "f" ]; then
      echo "recovery finished; the server accepts writes on port $port"
      exit 0
    fi
    sleep 1
  done
  echo "error: recovery did not finish; see $data/restore.log" >&2
  exit 1
fi
