#!/usr/bin/env bash
# Demonstration of PostgreSQL backup and restore into an empty database (T3.7).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

PG_URL_BASE="${PG_URL_BASE:-postgres://postgres:postgres@127.0.0.1:54321}"
SRC_DB="falak_backup_src"
DST_DB="falak_backup_dst"

SRC_URL="${PG_URL_BASE}/${SRC_DB}"
DST_URL="${PG_URL_BASE}/${DST_DB}"

echo "==> Preparing PostgreSQL test databases..."

PG_CONTAINER="falak-test-postgres"

# The official image first runs a temporary server (unix socket only) to initialise, then stops it
# and starts the real one. pg_isready on the socket succeeds against the temporary server, so wait
# for a real query over TCP (which only the final server offers) to succeed twice in a row.
wait_for_postgres() {
  local ok=0
  for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" psql -h 127.0.0.1 -U postgres -d postgres -Atc 'select 1' >/dev/null 2>&1; then
      ok=$((ok + 1))
      if [ "$ok" -ge 2 ]; then
        return 0
      fi
    else
      ok=0
    fi
    sleep 1
  done
  echo "Error: PostgreSQL in ${PG_CONTAINER} did not become ready." >&2
  return 1
}

# Run SQL against the maintenance database; any failure aborts the script.
psql_cmd() {
  docker exec -i "$PG_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c "$1" >/dev/null
}

wait_for_postgres

psql_cmd "DROP DATABASE IF EXISTS ${SRC_DB};"
psql_cmd "DROP DATABASE IF EXISTS ${DST_DB};"
psql_cmd "CREATE DATABASE ${SRC_DB};"
psql_cmd "CREATE DATABASE ${DST_DB};"

echo "==> Populating source database (${SRC_DB}) with sample data..."
docker exec -i falak-test-postgres psql -U postgres -d "${SRC_DB}" << 'EOF' >/dev/null
CREATE TABLE "_falak_migrations" (
    "version" bigint NOT NULL,
    "content_hash" text NOT NULL PRIMARY KEY,
    "checksum" text NOT NULL,
    "applied_at" timestamptz NOT NULL
);

INSERT INTO "_falak_migrations" VALUES (1, 'hash_initial_notebook', 'chk_initial_123', NOW());

CREATE TABLE "notes" (
    id uuid PRIMARY KEY,
    title text NOT NULL,
    body text,
    archived boolean NOT NULL DEFAULT false,
    owner_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

INSERT INTO "notes" (id, title, body, owner_id) VALUES
    ('00000000-0000-0000-0000-000000000001', 'First Backup Note', 'Crucial mission data', '00000000-0000-0000-0000-00000000000a'),
    ('00000000-0000-0000-0000-000000000002', 'Second Backup Note', 'Financial ledger transaction', '00000000-0000-0000-0000-00000000000a'),
    ('00000000-0000-0000-0000-000000000003', 'Third Note', 'Encrypted secret record', '00000000-0000-0000-0000-00000000000b');
EOF

SRC_COUNT=$(docker exec -i falak-test-postgres psql -U postgres -d "${SRC_DB}" -t -c "SELECT count(*) FROM notes;" | tr -d ' ')
echo "==> Source database has ${SRC_COUNT} notes."

# Verify target database is completely empty
DST_TABLES=$(docker exec -i falak-test-postgres psql -U postgres -d "${DST_DB}" -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')
if [ "$DST_TABLES" != "0" ]; then
  echo "Error: Target database is not empty!" >&2
  exit 1
fi
echo "==> Confirmed: Target database (${DST_DB}) is 100% empty (0 tables)."

echo "==> Executing backup of source database..."
DATABASE_URL="${SRC_URL}" BACKUP_DIR="${work}" BACKUP_NAME="demo_backup" "$root/scripts/backup/postgres-backup.sh"

DUMP_FILE="${work}/demo_backup.dump"
if [ ! -f "$DUMP_FILE" ]; then
  echo "Error: Dump file was not created!" >&2
  exit 1
fi

echo "==> Executing restore into empty target database (${DST_DB})..."
DATABASE_URL="${DST_URL}" "$root/scripts/backup/postgres-restore.sh" "$DUMP_FILE"

echo "==> Verifying restored target database..."
RESTORED_MIGRATIONS=$(docker exec -i falak-test-postgres psql -U postgres -d "${DST_DB}" -t -c "SELECT count(*) FROM _falak_migrations;" | tr -d ' ')
RESTORED_COUNT=$(docker exec -i falak-test-postgres psql -U postgres -d "${DST_DB}" -t -c "SELECT count(*) FROM notes;" | tr -d ' ')

echo "==> Restored tables summary:"
echo "    _falak_migrations: ${RESTORED_MIGRATIONS} row(s)"
echo "    notes:             ${RESTORED_COUNT} row(s)"

if [ "$RESTORED_COUNT" != "$SRC_COUNT" ] || [ "$RESTORED_MIGRATIONS" != "1" ]; then
  echo "Error: Restored record count mismatch!" >&2
  exit 1
fi

# Verify exact note contents match
TITLE1=$(docker exec -i falak-test-postgres psql -U postgres -d "${DST_DB}" -t -c "SELECT title FROM notes WHERE id = '00000000-0000-0000-0000-000000000001';" | tr -d ' \n')
if [ "$TITLE1" != "FirstBackupNote" ]; then
  echo "Error: Restored note title mismatch: $TITLE1" >&2
  exit 1
fi

# Cleanup test databases
psql_cmd "DROP DATABASE IF EXISTS ${SRC_DB};"
psql_cmd "DROP DATABASE IF EXISTS ${DST_DB};"

echo
echo "================================================================================"
echo "DEMONSTRATION PASSED: 100% of data successfully restored into an empty database!"
echo "================================================================================"
