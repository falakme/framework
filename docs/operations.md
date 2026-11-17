# Operating Falak: high availability, recovery, emergency access, rotation, objectives

Targets: **RPO 5 minutes, RTO 1 hour** for PostgreSQL apps (ARCHITECTURE §4.11). The drill
`scripts/smoke/dr.sh` measures both and fails if either is missed.

## 1. Office high availability

Run two or more Office instances on one PostgreSQL database behind a load balancer that
checks `/readyz` (`deploy/office/docker-compose.ha.yml`). There is no leader. Everything the
instances must agree on is in the database:

| State | Where |
| :-- | :-- |
| Signing keys and session keys | `office_keystore`; an instance re-reads it every 2 s, so a rotation through one instance reaches the others without a restart |
| Revocation feed, enrollments, request nonces, audit chain | their own tables |
| Tenant data keys | `office_deks`, wrapped by `FALAK_VAULT_KEK` (give every instance the same value) |

An existing single-instance Office keeps its keys: the files in the data directory seed the
database the first time it starts. `scripts/smoke/office-ha.sh` starts two instances, rotates
a key through one, kills it, and checks that sign-in and tokens continue on the other (first
successful sign-in about 0.03 s after the kill; run it with `OFFICE_DATABASE_URL` for
PostgreSQL). The database is then the single point of failure: use a managed or replicated
service. Apps do not need changes; tier 2 and 3 apps already ride out an Office outage.

## 2. Disaster recovery (every database to a point in time)

1. **Continuous WAL archiving** on the cluster: `wal_level=replica`, `archive_mode=on`,
   `archive_command='test ! -f /archive/%f && cp %p /archive/%f'` (or `pgBackRest`/`WAL-G` to
   object storage), `archive_timeout=60`. With a 60 s timeout, at most 60 s of writes are
   not yet archived: that is the RPO bound, well inside 5 minutes.
2. **Base backups**, daily: `scripts/backup/pitr-base.sh /backups/base-<date>` (checksummed,
   verified with `pg_verifybackup`, manifest hash stored beside it). Keep the base backups and
   the archive on storage the database host cannot delete, with the encryption key held apart
   from the database credentials.
3. **Restore**, when something is destroyed or corrupted:

   ```
   scripts/backup/pitr-restore.sh --base /backups/base-<date> --archive /archive \
     --data /var/lib/postgresql/restore --target-time '2026-11-16 14:03:00+00' --start
   ```

   It checks the base backup, copies it, writes the recovery settings and (with `--start`)
   starts PostgreSQL and waits for recovery to finish. The whole cluster is restored, so
   Office's database and every app's database come back at the same moment. Choose the time
   just before the damage. Then point Office and the apps at the restored server.
4. **After the restore**: start Office (its signing keys and audit chain are in the
   database, so they come back too), check `GET /v1/_office/audit/verify`, and if any app
   credential might have been exposed, rotate it (section 4).

Caveat: PostgreSQL's `DROP DATABASE` first marks the database invalid with a change that
recovery replays even when stopping just before the drop. To recover from an accidental
`DROP DATABASE`, restore to an earlier time (before the statement started) or use
`recovery_target_lsn`; for dropped tables, schemas or bad migrations, the time target works as
shown.

`scripts/smoke/dr.sh` is the drill: it runs the above in Docker, destroys both databases,
restores them, rotates a compromised app credential, and prints the time taken and the data
lost. The step-by-step logical restore (`pg_dump`) in `docs/postgres-backup-and-restore.md`
remains for single-database moves.

## 3. Break-glass (emergency access)

```
falak breakglass request --office https://office.example.com --email me@example.com \
  --password-env PW --app ledger --reason "ledger stuck, auditors waiting" --minutes 20
falak breakglass approve --id <id> ...     # a different administrator; required for tier 3
falak breakglass claim   --id <id> ...     # the requester; prints the token once
```

* A reason of at least 10 characters is required and goes into the audit chain.
* Access is time-limited: at most 60 minutes (30 for tier 3). A request must be approved and
  claimed within 30 minutes. The token has the role `break_glass`, is for that one app, and
  expires on its own; `DELETE /v1/_office/breakglass/<id>` ends it early and revokes it.
* Every step (requested, approved, used, ended) is an audit entry and an alert: the log line,
  `FALAK_ALERT_WEBHOOK` if set, and an `alert_page` audit entry.
* Tier 3 apps need a second administrator: the approver cannot be the requester, and the
  requester cannot collect the token until someone else approves.
* Policies must opt in: an app grants nothing to `break_glass` unless its policy names that role.

## 4. Rotation and audit anchoring (Vault)

| What | How |
| :-- | :-- |
| Office signing key | `falak office rotate-key` (old key keeps verifying until `--retire`) |
| A compromised app credential | `falak office rotate-credential --app <name> ...`: the app's key stops working at once, its passport is revoked in the feed, and a one-time enrollment token lets the real app enroll again with a new key (give it to the CLI through the environment: `falak office enroll --office <url> --token-env VAR`, or `FALAK_ENROLL_TOKEN`) |
| Tenant data key (DEK) | `POST /v1/_office/vault/deks/<app>:<tenant>/rotate` adds a version and retires the old one (still readable, to re-encrypt with); `.../retire-old` deletes retired versions after re-encryption; `DELETE .../deks/<app>:<tenant>` erases a tenant's keys |
| Key-encryption key (KEK) | `POST /v1/_office/vault/kek/rotate` re-wraps every DEK under a new KEK (no data is re-encrypted). With `FALAK_VAULT_KEK` set, rotate it in your secret manager instead |

Apps fetch their tenants' data keys with a signed request to `POST /v1/_office/vault/dek`
(`{"tenant": "..."}`); an app can only reach keys under its own name.

**Audit anchoring.** Every 5 minutes (`FALAK_AUDIT_ANCHOR_SECS`) Office signs the head of its
audit chain and writes it as a new file to `FALAK_AUDIT_ANCHOR_DIR` (put write-once storage
there) and/or POSTs it to `FALAK_AUDIT_ANCHOR_URL`. `falak-office audit verify [--anchors DIR]`
(or `GET /v1/_office/audit/verify`) checks the whole chain and every anchor: a rewritten
history or a truncated tail fails even if every hash in the database was recomputed.

## 5. Service-level objectives and alerts

Office counts every response (status and latency) and checks its database; with the audit
anchor age and signing-key age, that gives five objectives (`GET /v1/_office/slo`):

| Objective | Target | Page / ticket |
| :-- | :-- | :-- |
| availability | 99.9% of responses not 5xx | page: 5 min and 1 h both burning at 14.4x the error budget; ticket: 1 h at 6x |
| latency | 99% of responses under 500 ms | same rule |
| database | readiness check passes | page |
| audit anchor | newest anchor under 1 hour old (when anchoring is on) | ticket |
| signing key age | rotated within 90 days | ticket |

A change of state sends one alert (log line, audit entry, `FALAK_ALERT_WEBHOOK`), and one
recovery notice. For Prometheus, set `FALAK_METRICS_TOKEN` (when it is unset or empty, `/metrics` answers 404), scrape `/metrics` with that bearer
token, and load `deploy/office/alerts.yml`. The Observatory page in Studio shows the same
objectives, the audit chain and break-glass requests.
