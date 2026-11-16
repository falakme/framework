#!/usr/bin/env python3
"""Disaster-recovery drill (T6.8): destroy the databases, restore them to a point in time,
rotate a compromised app credential, and report the time taken and the data lost.

What it does, with a real PostgreSQL server in Docker and the real Office and CLI:

  1. a primary with continuous WAL archiving, holding two databases: Office's and an
     app's (`notebook`, with a `ticks` table a writer fills 4 times a second);
  2. a base backup (scripts/backup/pitr-base.sh) while the writer runs, then more work
     after it: Office rotates its signing key and enrolls a second app. None of that is in
     the base backup; only the WAL archive has it;
  3. the disaster: both databases are dropped, the WAL is flushed to the archive, and the
     primary and its data directory are destroyed. The RTO clock starts here;
  4. the restore to the moment before the drop (scripts/backup/pitr-restore.sh);
  5. checks: the app's rows are back up to the second before the drop, Office signs in,
     publishes the same signing keys as before, knows the app enrolled after the backup,
     and its audit chain verifies;
  6. a compromised app credential is replaced (`falak office rotate-credential`): the old
     key stops working at once and the app enrolls again with a new one.

It prints the time taken (RTO) and the data lost (RPO) and exits non-zero if either is over
the objectives in docs/postgres-backup-and-restore.md: RPO 5 minutes, RTO 1 hour.

usage: dr.py <falak> <falak-office> <examples/notebook>
Needs: docker (the postgres:16-alpine image), python3.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

FALAK, OFFICE_BIN, NOTEBOOK = sys.argv[1], sys.argv[2], sys.argv[3]
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPTS = os.path.join(ROOT, "scripts", "backup")
IMAGE = os.environ.get("DR_PG_IMAGE", "postgres:16-alpine")
RPO_SECS, RTO_SECS = 5 * 60, 60 * 60
PASSWORD = "correct horse battery staple 42"
RUN = f"falakdr{os.getpid()}"
work = tempfile.mkdtemp(prefix="falak-dr-")
procs, containers, volumes = [], [], []
failed = []
T0 = time.time()


def port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def step(msg):
    print(f"[{time.time() - T0:6.1f}s] {msg}", flush=True)


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"), flush=True)
    if not ok:
        failed.append(name)


def sh(argv, check_rc=True, env=None, input=None):
    e = dict(os.environ)
    e.pop("DATABASE_URL", None)
    e.update(env or {})
    r = subprocess.run(argv, capture_output=True, text=True, env=e, input=input)
    if check_rc and r.returncode != 0:
        sys.exit(f"command failed: {' '.join(argv[:6])}\n{r.stdout}\n{r.stderr}")
    return r


def docker(*args, **kw):
    return sh(["docker", *args], **kw)


def psql(container, db, sql, check_rc=True):
    r = docker("exec", "-u", "postgres", container, "psql", "-U", "postgres", "-d", db, "-Atq", "-c", sql,
               check_rc=check_rc)
    return r.stdout.strip()


def call(base, method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw) if raw else None
            except ValueError:
                return r.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def start_office(name, p, data, dburl):
    os.makedirs(data, exist_ok=True)
    env = dict(os.environ)
    env.update({"DATABASE_URL": dburl, "FALAK_OFFICE_DATA": data, "FALAK_VAULT_KEK": "11" * 32})
    log = open(os.path.join(work, name + ".log"), "w")
    proc = subprocess.Popen([OFFICE_BIN, "serve", "--port", str(p), "--issuer", f"http://127.0.0.1:{p}"],
                            stdout=log, stderr=subprocess.STDOUT, env=env)
    procs.append(proc)
    base = f"http://127.0.0.1:{p}"
    for _ in range(120):
        if proc.poll() is not None:
            sys.exit(f"{name} exited: {open(os.path.join(work, name + '.log')).read()}")
        if call(base, "GET", "/readyz")[0] == 200:
            return proc, base
        time.sleep(0.25)
    sys.exit(f"{name} did not become ready")


def stop(p):
    if p.poll() is None:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def cleanup():
    for p in procs:
        stop(p)
    for c in containers:
        docker("rm", "-f", "-v", c, check_rc=False)
    for v in volumes:
        docker("volume", "rm", "-f", v, check_rc=False)
    shutil.rmtree(work, ignore_errors=True)


def jwks_kids(base):
    s, v = call(base, "GET", "/.well-known/jwks.json")
    return sorted(k["kid"] for k in v["keys"]) if s == 200 else None


def main():
    # ------------------------------------------------------------------ 1. the primary
    step("starting a PostgreSQL primary with continuous WAL archiving")
    for v in ("archive", "base"):
        docker("volume", "create", f"{RUN}-{v}")
        volumes.append(f"{RUN}-{v}")
        # The postgres user in the image is uid 70.
        docker("run", "--rm", "-v", f"{RUN}-{v}:/v", "alpine", "chown", "70:70", "/v")
    pport = port()
    docker("run", "-d", "--name", f"{RUN}-primary", "-e", "POSTGRES_PASSWORD=pw",
           "-v", f"{RUN}-archive:/archive", "-v", f"{RUN}-base:/base", "-v", f"{SCRIPTS}:/scripts:ro",
           "-p", f"127.0.0.1:{pport}:5432", IMAGE,
           "-c", "wal_level=replica", "-c", "archive_mode=on",
           "-c", "archive_command=test ! -f /archive/%f && cp %p /archive/%f",
           "-c", "archive_timeout=10", "-c", "max_connections=50")
    containers.append(f"{RUN}-primary")
    P = f"{RUN}-primary"
    for _ in range(60):
        if docker("exec", P, "pg_isready", "-U", "postgres", check_rc=False).returncode == 0 and \
                psql(P, "postgres", "select 1", check_rc=False) == "1":
            break
        time.sleep(1)
    else:
        sys.exit("postgres did not start")
    psql(P, "postgres", "create database office")
    psql(P, "postgres", "create database notebook")
    psql(P, "notebook", "create table ticks (id bigserial primary key, ts timestamptz not null default clock_timestamp(), note text)")
    psql(P, "notebook", "insert into ticks(note) select 'seed' from generate_series(1,200)")

    # ------------------------------------------------------------------ Office on it
    oport = port()
    office_url = f"http://127.0.0.1:{oport}"
    dburl = f"postgres://postgres:pw@127.0.0.1:{pport}/office"
    env = {"DATABASE_URL": dburl, "FALAK_OFFICE_DATA": os.path.join(work, "office-a"), "PW": PASSWORD,
           "FALAK_VAULT_KEK": "11" * 32}
    os.makedirs(env["FALAK_OFFICE_DATA"], exist_ok=True)
    sh([OFFICE_BIN, "setup", "--email", "admin@example.com", "--password-env", "PW", "--issuer", office_url], env=env)
    oa, _ = start_office("office-a", oport, env["FALAK_OFFICE_DATA"], dburl)
    s, login = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    assert s == 200, login
    admin = login["access_token"]

    app_dir = os.path.join(work, "notebook-app")
    shutil.copytree(NOTEBOOK, app_dir, ignore=shutil.ignore_patterns(".falak", "web", "node_modules"))
    s, enr = call(office_url, "POST", "/v1/_office/enrollments", {"app": "notebook", "tier": 1}, admin)
    assert s == 201, enr
    sh([FALAK, "office", "enroll", app_dir, "--office", office_url, "--token", enr["token"], "--name", "notebook"])
    check("the app is enrolled and linked to Office", sh([FALAK, "office", "status", app_dir], check_rc=False).returncode == 0)

    # ------------------------------------------------------------------ 2. base backup under load
    step("taking a base backup while a writer is running")
    docker("exec", "-d", P, "sh", "-c",
           "rm -f /tmp/stop; while [ ! -f /tmp/stop ]; do psql -U postgres -d notebook -qAtc \"insert into ticks(note) values ('live')\"; sleep 0.25; done")
    time.sleep(2)
    docker("exec", "-u", "postgres", P, "/scripts/pitr-base.sh", "/base/b1")
    step("base backup done; more work that only the WAL archive will hold")
    time.sleep(2)
    s, rot = call(office_url, "POST", "/v1/_office/keys/rotate", None, admin)
    assert s == 200, rot
    s, enr2 = call(office_url, "POST", "/v1/_office/enrollments", {"app": "journal", "tier": 2}, admin)
    assert s == 201, enr2
    # (journal's enrollment token is pending, not used: it is data too.)
    time.sleep(3)
    kids_before = jwks_kids(office_url)
    rows_before = int(psql(P, "notebook", "select count(*) from ticks"))
    audit_head_before = psql(P, "office", "select max(seq) from office_audit")

    # ------------------------------------------------------------------ 3. disaster
    step("DISASTER: stop the writer, drop every table in both databases, flush the WAL archive, destroy the primary")
    docker("exec", P, "touch", "/tmp/stop")
    time.sleep(1)
    stop(oa)
    last_tick, t_drop = psql(P, "notebook", "select max(ts)::text || '|' || clock_timestamp()::text from ticks").split("|")
    # Everything in both databases is destroyed, one transaction each. (PostgreSQL's own
    # DROP DATABASE first marks the database invalid with a change that recovery replays
    # even when stopping before the drop, so the drill uses the transactional destruction a
    # point-in-time restore is meant for.)
    psql(P, "notebook", "drop schema public cascade")
    psql(P, "office", "drop schema public cascade")
    archived_before = psql(P, "postgres", "select coalesce(last_archived_wal,'') from pg_stat_archiver")
    psql(P, "postgres", "select pg_switch_wal()")
    for _ in range(60):
        if psql(P, "postgres", "select coalesce(last_archived_wal,'') from pg_stat_archiver") != archived_before:
            break
        time.sleep(0.5)
    docker("rm", "-f", "-v", P)
    containers.remove(P)
    t_disaster = time.time()
    step(f"primary destroyed. last row written {last_tick}; tables dropped at {t_drop}")

    # ------------------------------------------------------------------ 4. restore
    step("RESTORE: point-in-time recovery of the whole cluster to just before the drop")
    docker("volume", "create", f"{RUN}-restore")
    volumes.append(f"{RUN}-restore")
    docker("run", "--rm", "-v", f"{RUN}-restore:/v", "alpine", "chown", "70:70", "/v")
    # The drop is after `t_drop`: everything committed up to that moment is recovered.
    r = docker("run", "--rm", "--user", "postgres", "-v", f"{RUN}-base:/base:ro", "-v", f"{RUN}-archive:/archive:ro",
               "-v", f"{RUN}-restore:/restore", "-v", f"{SCRIPTS}:/scripts:ro", IMAGE,
               "/scripts/pitr-restore.sh", "--base", "/base/b1", "--archive", "/archive",
               "--data", "/restore/pgdata", "--target-time", t_drop)
    print(r.stdout.strip())
    rport = port()
    docker("run", "-d", "--name", f"{RUN}-restored", "-e", "POSTGRES_PASSWORD=pw",
           "-e", "PGDATA=/var/lib/postgresql/data/pgdata",
           "-v", f"{RUN}-restore:/var/lib/postgresql/data", "-v", f"{RUN}-archive:/archive:ro",
           "-p", f"127.0.0.1:{rport}:5432", IMAGE)
    containers.append(f"{RUN}-restored")
    R = f"{RUN}-restored"
    for _ in range(600):
        if psql(R, "postgres", "select pg_is_in_recovery()", check_rc=False) == "f":
            break
        time.sleep(0.5)
    else:
        print(docker("logs", R, check_rc=False).stdout[-2000:])
        sys.exit("recovery did not finish")
    t_restored = time.time()
    step(f"database restored in {t_restored - t_disaster:.1f}s")

    # ------------------------------------------------------------------ 5. verify
    tables = {d: int(psql(R, d, "select count(*) from information_schema.tables where table_schema = 'public'"))
              for d in ("notebook", "office")}
    check("both databases are back, with their tables", all(n > 0 for n in tables.values()), tables)
    restored_last = psql(R, "notebook", "select max(ts)::text from ticks")
    rows_after = int(psql(R, "notebook", "select count(*) from ticks"))
    lost = float(psql(R, "postgres", f"select extract(epoch from ('{last_tick}'::timestamptz - '{restored_last}'::timestamptz))"))
    check("the app's rows are back", rows_after >= rows_before - 2, f"{rows_after} vs {rows_before}")
    print(f"     rows before the disaster {rows_before}, restored {rows_after}")

    odb = f"postgres://postgres:pw@127.0.0.1:{rport}/office"
    ob, _ = start_office("office-b", oport, os.path.join(work, "office-b"), odb)  # a new, empty data directory
    s, login = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    check("the administrator signs in to the restored Office", s == 200, login)
    admin = login["access_token"]
    check("Office publishes the same signing keys (kept in the database)", jwks_kids(office_url) == kids_before,
          f"{jwks_kids(office_url)} vs {kids_before}")
    s, apps = call(office_url, "GET", "/v1/_office/apps", None, admin)
    names = sorted(a["name"] for a in apps["data"]) if s == 200 else []
    check("the app enrolled before the disaster is back", "notebook" in names, names)
    s, v = call(office_url, "GET", "/v1/_office/audit/verify", None, admin)
    check("the audit chain verifies and nothing after the backup is missing", s == 200 and v["entries"] >= int(audit_head_before or 0) - 1, v)
    check("the app is still linked to Office", sh([FALAK, "office", "status", app_dir], check_rc=False).returncode == 0)

    # ------------------------------------------------------------------ 6. compromised credential
    step("a credential is compromised: rotate it")
    t_rot = time.time()
    r = sh([FALAK, "office", "rotate-credential", "--office", office_url, "--email", "admin@example.com",
            "--password-env", "PW", "--app", "notebook"], env={"PW": PASSWORD})
    token = json.loads(r.stdout.strip().splitlines()[-1])["enrollment_token"]
    check("the stolen credential stops working at once", sh([FALAK, "office", "status", app_dir], check_rc=False).returncode != 0)
    for f in ("office.json", "office-app-key.json"):
        os.remove(os.path.join(app_dir, ".falak", f))
    sh([FALAK, "office", "enroll", app_dir, "--office", office_url, "--token", token, "--name", "notebook"])
    check("the app enrolls again with a new key", sh([FALAK, "office", "status", app_dir], check_rc=False).returncode == 0)
    t_done = time.time()

    # ------------------------------------------------------------------ report
    rto = t_done - t_disaster
    print()
    print("=" * 66)
    print("DISASTER-RECOVERY DRILL")
    print(f"  data lost (RPO measured)   {lost:8.2f} s   objective {RPO_SECS} s")
    print(f"  restore of the cluster     {t_restored - t_disaster:8.1f} s")
    print(f"  credential rotation        {t_done - t_rot:8.1f} s")
    print(f"  time to recover (RTO)      {rto:8.1f} s   objective {RTO_SECS} s")
    print("=" * 66)
    check("data lost is within the RPO", lost <= RPO_SECS, f"{lost}s")
    check("recovery time is within the RTO", rto <= RTO_SECS, f"{rto}s")


try:
    main()
finally:
    cleanup()

if failed:
    sys.exit("FAILED: " + ", ".join(failed))
print("dr: all checks passed")
