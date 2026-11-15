# PostgreSQL Backup and Restore Procedure

**Target:** Enterprise recovery objectives for Falak applications on PostgreSQL:
* **Recovery Point Objective (RPO):** $\le 5$ minutes
* **Recovery Time Objective (RTO):** $\le 1$ hour

---

## 1. Architecture & Strategy

Falak's PostgreSQL deployment strategy utilizes a two-tier backup architecture:
1. **Continuous WAL Archiving / Physical Replication:** For production high-availability instances, write-ahead logs (WAL) are streamed to replica nodes or an object storage bucket (e.g. via `pgBackRest` or managed cloud backups).
2. **Logical Snapshot Archives (`pg_dump -Fc`):** Automated snapshots scheduled periodically into encrypted object storage (S3-compatible bucket) with SHA-256 integrity manifests.

Logical snapshots use PostgreSQL's custom archive format (`-Fc`), which provides:
* **Snapshot Consistency:** Guarantees transaction-isolated snapshots without table-level write locks.
* **Built-in Compression:** Reduces network bandwidth and storage overhead by 70–80%.
* **Parallel Restore:** Enables multi-threaded restoration (`pg_restore -j <cores>`).
* **Granular Recovery:** Supports selective table, schema, or data-only restore.

---

## 2. Taking an Automated Backup

Run `scripts/backup/postgres-backup.sh`:

```bash
DATABASE_URL="postgres://postgres:postgres@localhost:5432/notebook" \
BACKUP_DIR="./backups" \
./scripts/backup/postgres-backup.sh
```

### Generated Files:
1. `falak_backup_<YYYYMMDD_HHMMSSZ>.dump`: The compressed custom archive.
2. `falak_backup_<YYYYMMDD_HHMMSSZ>.sha256`: SHA-256 hash manifest for tamper verification.

### Offsite Upload to S3 Bucket:
```bash
# Example AWS CLI / MinIO S3 sync
aws s3 cp ./backups/falak_backup_20261115_120000Z.dump s3://falak-backups/notebook/
aws s3 cp ./backups/falak_backup_20261115_120000Z.sha256 s3://falak-backups/notebook/
```

---

## 3. Written Restore Procedure

Follow these steps to restore a backup into a clean or empty PostgreSQL database.

### Step 1: Provision an Empty Database
If restoring into a new database server or recovery cluster:
```sql
CREATE DATABASE notebook_restore;
```

### Step 2: Retrieve the Backup and Manifest from Object Storage
```bash
aws s3 cp s3://falak-backups/notebook/falak_backup_20261115_120000Z.dump ./
aws s3 cp s3://falak-backups/notebook/falak_backup_20261115_120000Z.sha256 ./
```

### Step 3: Verify Cryptographic Checksum
Before executing restore operations on untrusted archives, verify the SHA-256 checksum:
```bash
shasum -a 256 -c falak_backup_20261115_120000Z.sha256
```
If the check fails, abort immediately; the archive may be corrupted or tampered with.

### Step 4: Run the Restore Script
Run `scripts/backup/postgres-restore.sh`:
```bash
DATABASE_URL="postgres://postgres:postgres@localhost:5432/notebook_restore" \
./scripts/backup/postgres-restore.sh ./falak_backup_20261115_120000Z.dump
```

Or using `pg_restore` directly:
```bash
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  -d "postgres://postgres:postgres@localhost:5432/notebook_restore" \
  ./falak_backup_20261115_120000Z.dump
```

### Step 5: Post-Restore Verification
1. Verify tables and migrations are present:
   ```sql
   SELECT * FROM "_falak_migrations";
   SELECT count(*) FROM "notes";
   ```
2. Start the Falak service against the restored database:
   ```bash
   DATABASE_URL="postgres://postgres:postgres@localhost:5432/notebook_restore" falak serve examples/notebook --port 8787
   ```
3. Check application readiness:
   ```bash
   curl -fsS http://127.0.0.1:8787/readyz
   ```
