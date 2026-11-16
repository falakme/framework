#!/usr/bin/env bash
# Ledger smoke test (T8.6): the double-spend check.
#
#   DATABASE_URL=postgres://user:pass@host/db scripts/smoke/ledger.sh
#
# Needs PostgreSQL 16 and `psql`. The database user must own the ledger tables (it
# creates them). Safe to run again on the same database: every run uses its own accounts.
#
# What it checks:
#   1. 200 concurrent transfers, 40 from each of 5 accounts that hold 1000 and send 100
#      each time (4000 against 1000), then concurrent settlements to an external rail.
#   2. Afterwards no account is negative, debits equal credits, and no transaction is
#      unbalanced (checked here with SQL, independent of the load generator).
#   3. Reconciling the external statement, which the load generator wrote from the
#      settlements it saw acknowledged, shows zero differences; a statement with a
#      missing, a changed and an invented line shows exactly those differences.
#   4. The application role can read and insert but not update, delete or truncate, and
#      the table owner cannot either (trigger).
set -uo pipefail

: "${DATABASE_URL:?set DATABASE_URL to a PostgreSQL 16 database}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
run="$(date +%s)-$$"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$root" || exit 1
fail=0
check() { # check <name> <ok:0|1>
  if [ "$2" = "0" ]; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}
q() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -At -c "$1"; }
falak() { cargo run -q -p falak-cli -- "$@"; }

echo "==> building"
cargo build -q -p falak-cli -p falak-ledger --example ledger_load || exit 1

echo "==> schema"
falak ledger init --database-url "$DATABASE_URL" || exit 1

echo "==> load: concurrent transfers that exceed every balance, then settlements"
out="$(cargo run -q -p falak-ledger --example ledger_load -- "$DATABASE_URL" "$run" "$work/statement.csv")"
status=$?
echo "$out"
check "load generator finished and its own invariants held" "$status"

echo "==> invariants, checked in SQL"
check "no account is negative" "$([ "$(q "SELECT count(*) FROM (SELECT a.id FROM ledger_accounts a LEFT JOIN ledger_entries e ON e.account_id = a.id WHERE NOT a.allow_negative GROUP BY a.id HAVING COALESCE(SUM(e.amount),0) < 0) x")" = 0 ]; echo $?)"
check "debits equal credits (all entries sum to zero)" "$([ "$(q "SELECT COALESCE(SUM(amount),0) FROM ledger_entries")" = 0 ]; echo $?)"
check "every transaction balances" "$([ "$(q "SELECT count(*) FROM (SELECT tx_id, currency FROM ledger_entries GROUP BY 1,2 HAVING SUM(amount) <> 0) x")" = 0 ]; echo $?)"
check "no double spend: exactly 10 transfers posted per source" "$([ "$(q "SELECT count(*) FROM ledger_transactions t WHERE t.kind='transfer' AND EXISTS (SELECT 1 FROM ledger_entries e WHERE e.tx_id=t.id AND e.account_id LIKE 'src-$run-%' AND e.amount < 0)")" = 50 ]; echo $?)"

echo "==> reconciliation against the external statement"
falak ledger import --statement "$work/statement.csv" --statement-id "smoke-$run" \
  --ledger-account "rail-$run" --database-url "$DATABASE_URL" || fail=1
falak ledger reconcile --statement-id "smoke-$run" --database-url "$DATABASE_URL"
check "reconciliation difference is zero" "$?"

# Break the statement three ways: drop a line, change an amount, invent a line.
{
  head -n 1 "$work/statement.csv"
  tail -n +3 "$work/statement.csv" | sed '1s/,USD,50$/,USD,51/'
  echo "INVENTED-$run,USD,7"
} > "$work/broken.csv"
falak ledger import --statement "$work/broken.csv" --statement-id "smoke-broken-$run" \
  --ledger-account "rail-$run" --database-url "$DATABASE_URL" || fail=1
report="$(falak ledger reconcile --statement-id "smoke-broken-$run" --database-url "$DATABASE_URL")"
code=$?
echo "$report"
check "a broken statement is detected (exit 1)" "$([ "$code" = 1 ]; echo $?)"
check "and reports 3 differences" "$(echo "$report" | grep -q '^differences: 3$'; echo $?)"

echo "==> history cannot be rewritten"
role="falak_ledger_smoke_$$"
psql "$DATABASE_URL" -q -c "CREATE ROLE $role NOLOGIN" || fail=1
falak ledger init --database-url "$DATABASE_URL" --app-role "$role" >/dev/null || fail=1
for stmt in "UPDATE ledger_entries SET amount = amount" "DELETE FROM ledger_entries" "TRUNCATE ledger_entries"; do
  psql "$DATABASE_URL" -q -c "SET ROLE $role; $stmt" >/dev/null 2>&1
  check "application role refused: $stmt" "$([ $? != 0 ]; echo $?)"
  psql "$DATABASE_URL" -q -c "$stmt" >/dev/null 2>&1
  check "table owner refused: $stmt" "$([ $? != 0 ]; echo $?)"
done
psql "$DATABASE_URL" -q -c "SET ROLE $role; SELECT count(*) FROM ledger_entries" >/dev/null 2>&1
check "application role can read" "$?"
psql "$DATABASE_URL" -q -c "RESET ROLE; REVOKE ALL ON ledger_accounts, ledger_transactions, ledger_entries, ledger_idempotency, ledger_statements, ledger_statement_lines FROM $role; REVOKE USAGE, SELECT ON SEQUENCE ledger_entries_id_seq FROM $role; DROP ROLE $role" >/dev/null 2>&1

if [ "$fail" = 0 ]; then echo "ledger smoke test passed"; else echo "ledger smoke test FAILED"; fi
exit "$fail"
