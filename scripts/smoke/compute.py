#!/usr/bin/env python3
"""Office Compute end to end, with real processes (T7.6).

Starts Office, queues a multi-minute SecuraBlock scan, starts a worker, kills that worker
part-way through, and checks that a second worker finishes the job exactly once, and that
the worker host listens on no port. It also checks dead-lettering, worker revocation and
job-scoped credentials.

usage: compute.py <falak> <falak-office> <falak-worker> <testdata/apps/securablock>
Environment: SMOKE_JOB_SECONDS (default 150) sets how long the scan runs.
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
import _http
import uuid

FALAK, OFFICE_BIN, WORKER_BIN, APP = sys.argv[1:5]
JOB_SECONDS = int(os.environ.get("SMOKE_JOB_SECONDS", "150"))
LEASE_MS = 6000
PASSWORD = "correct horse battery staple 42"

work = tempfile.mkdtemp(prefix="falak-compute-smoke-")
procs, failed = [], []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"))
    if not ok:
        failed.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def call(base, method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with _http.urlopen(req, timeout=10) as r:
            raw = r.read()
            try:
                return r.status, (json.loads(raw) if raw else None)
            except ValueError:
                return r.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except ValueError:
            return e.code, raw.decode(errors="replace")
    except Exception as e:  # connection refused and the like
        return 0, str(e)


def run(argv, env=None):
    e = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    e.update(env or {})
    r = subprocess.run(argv, capture_output=True, text=True, env=e)
    if r.returncode != 0:
        sys.exit(f"{' '.join(argv[:3])} failed: {r.stdout}{r.stderr}")
    return r.stdout


def start(argv, log, env=None, group=False):
    e = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    e.update(env or {})
    p = subprocess.Popen(argv, stdout=open(os.path.join(work, log), "w"),
                         stderr=subprocess.STDOUT, env=e, start_new_session=group)
    procs.append(p)
    return p


def stop(p):
    if p.poll() is None:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def listening(pid):
    """Sockets `pid` listens on or has bound for datagrams. Empty means no inbound port."""
    if shutil.which("lsof"):
        out = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN", "-iUDP"],
                             capture_output=True, text=True).stdout
        # `-a` with two -i options ORs them, which is what we want here.
        return [l for l in out.splitlines()[1:] if l.strip()]
    if shutil.which("ss"):
        out = subprocess.run(["ss", "-H", "-ltunp"], capture_output=True, text=True).stdout
        return [l for l in out.splitlines() if f"pid={pid}," in l]
    return None


def status(base, token, job_id):
    return call(base, "GET", f"/v1/_office/compute/jobs/{job_id}", token=token)[1] or {}


def wait_for(fn, seconds, every=0.5):
    end = time.time() + seconds
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


def main():
    # The scan's contract, compiled from the example the way a deployment would.
    app = os.path.join(work, "securablock")
    shutil.copytree(APP, app, ignore=shutil.ignore_patterns(".falak"))
    run([FALAK, "build", app])
    ir = json.load(open(os.path.join(app, ".falak", "ir.json")))
    contract = next(j for j in ir["jobs"] if j["name"] == "scan_artifact")
    # The process runner stands in for the container: same contract, local script.
    contract["command"] = [sys.executable, os.path.join(app, "worker", "scan.py")]
    contract["timeout_seconds"] = JOB_SECONDS + 120
    flaky = {**contract, "name": "flaky", "max_attempts": 1,
             "command": [sys.executable, "-c", "import sys; sys.exit(3)"]}
    flaky["input"] = []

    port = free_port()
    office_url = f"http://127.0.0.1:{port}"
    data = os.path.join(work, "office")
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "admin@example.com",
         "--password-env", "OFFICE_PW", "--role", "office_admin"], {"OFFICE_PW": PASSWORD})
    start([OFFICE_BIN, "serve", "--port", str(port), "--data", data, "--issuer", office_url], "office.log")
    for _ in range(80):
        if call(office_url, "GET", "/healthz")[0] == 200:
            break
        time.sleep(0.25)
    else:
        sys.exit(f"office did not start ({call(office_url, 'GET', '/healthz')}):\n" + open(os.path.join(work, "office.log")).read())
    s, v = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    check("the administrator signs in", s == 200, f"{s} {v}")
    admin = v["access_token"]

    def make_worker(name):
        s, v = call(office_url, "POST", "/v1/_office/compute/workers", {"name": name}, admin)
        assert s == 201, (s, v)
        return v["id"], v["credential"]

    def enqueue(job, payload, jid=None):
        body = {"job": job, "payload": payload}
        if jid:
            body["id"] = jid
        return call(office_url, "POST", "/v1/_office/compute/jobs", body, admin)

    # ---- a payload that breaks the contract is refused
    s, v = enqueue(contract, {"scan_id": "not-a-uuid", "content": "x"})
    check("a payload that breaks the job contract is refused", s == 400, f"{s} {v}")
    s, v = enqueue(contract, {"scan_id": str(uuid.uuid4()), "content": "x", "extra": 1})
    check("an unknown input is refused", s == 400, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/_office/compute/jobs",
                {"job": contract, "payload": {"scan_id": str(uuid.uuid4()), "content": "x"}})
    check("queuing a job needs a signed-in operator", s == 401, f"{s} {v}")

    # ---- the long scan, queued twice under one id: one job
    content = "ok line\nkey = AKIAABCDEFGHIJKLMNOP\npassword = \"correct-horse-battery\"\n"
    jid = str(uuid.uuid4())
    payload = {"scan_id": str(uuid.uuid4()), "content": content, "deep_seconds": JOB_SECONDS}
    s, v = enqueue(contract, payload, jid)
    check("the scan is queued", s == 202, f"{s} {v}")
    job_hex = v["id"]
    enqueue(contract, payload, jid)

    # ---- worker one takes it
    w1_id, w1_cred = make_worker("box-1")
    wenv = {"FALAK_WORKER_CREDENTIAL": w1_cred, "FALAK_WORKER_UNSAFE_PROCESS": "1"}
    wargs = ["--office", office_url, "--kinds", "scan_artifact,flaky", "--runner", "process",
             "--lease-ms", str(LEASE_MS), "--poll-ms", "500"]
    w1 = start([WORKER_BIN] + wargs, "worker1.log", wenv, group=True)
    held = wait_for(lambda: status(office_url, admin, job_hex).get("status") == "leased", 30)
    check("worker one leases the scan", bool(held))
    ports = listening(w1.pid)
    if ports is None:
        print("skip (neither lsof nor ss is installed): the worker host has no open inbound port")
    else:
        check("the worker host has no open inbound port", ports == [], ports)

    # ---- kill the worker, and its job, mid-scan
    time.sleep(min(30, JOB_SECONDS // 4))
    check("the scan is still running when worker one is killed",
          status(office_url, admin, job_hex).get("status") == "leased")
    os.killpg(w1.pid, signal.SIGKILL)
    w1.wait()
    print(f"killed worker one mid-scan; the lease ({LEASE_MS // 1000}s) must lapse")

    # ---- worker two finishes it
    w2_id, w2_cred = make_worker("box-2")
    start([WORKER_BIN] + wargs, "worker2.log", {**wenv, "FALAK_WORKER_CREDENTIAL": w2_cred}, group=True)
    done = wait_for(lambda: status(office_url, admin, job_hex).get("status") in ("done", "dead")
                    and status(office_url, admin, job_hex), JOB_SECONDS + 90, every=2)
    check("the scan finishes on the second worker", bool(done) and done["status"] == "done", done)
    done = done or {}
    check("it ran twice (once lost, once finished) and completed once", done.get("attempts") == 2, done)
    check("its result is the scan's", (done.get("result") or {}).get("finding_count") == 2, done)
    time.sleep(1)
    check("a finished job stays finished", status(office_url, admin, job_hex).get("status") == "done")

    # ---- a job that fails for good is dead-lettered, not retried forever
    s, v = enqueue(flaky, {})
    flaky_hex = v["id"]
    dead = wait_for(lambda: status(office_url, admin, flaky_hex).get("status") == "dead", 40)
    check("a job that fails on its last attempt is dead-lettered", bool(dead))
    s, v = call(office_url, "GET", "/v1/_office/compute/dead", token=admin)
    check("the dead-letter queue lists it", s == 200 and any(d["id"] == flaky_hex for d in v["dead"]), f"{s} {v}")

    # ---- credentials: a worker the administrator revokes is shut out at once
    w3_id, w3_cred = make_worker("box-3")
    s, v = call(office_url, "POST", "/v1/_office/compute/lease", {"kinds": ["scan_artifact"]}, w3_cred)
    check("a worker credential leases", s == 200, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/_office/compute/workers", {"name": "x"}, w3_cred)
    check("a worker credential cannot administer workers", s == 401, f"{s} {v}")
    s, v = call(office_url, "POST", f"/v1/_office/compute/workers/{w3_id}/revoke", token=admin)
    check("the administrator revokes the worker", s == 200, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/_office/compute/lease", {"kinds": ["scan_artifact"]}, w3_cred)
    check("a revoked worker is refused", s == 401, f"{s} {v}")

    # ---- credentials: the job's own credential works for its job only, and only while leased
    enqueue(contract, {"scan_id": str(uuid.uuid4()), "content": "x"})
    w4_id, w4_cred = make_worker("box-4")
    s, v = call(office_url, "POST", "/v1/_office/compute/lease", {"kinds": ["scan_artifact"], "lease_millis": 30000}, w4_cred)
    job = (v or {}).get("jobs", [{}])[0]
    token, lease = job.get("credential", ""), job.get("lease_id", "")
    check("a lease carries a job credential and the contract's egress list",
          token.startswith("jt_") and job.get("spec", {}).get("egress") == [], v)
    s, v = call(office_url, "POST", "/v1/_office/compute/job/result", {"result": {"ok": True}}, token)
    check("the job credential records that job's result", s == 200, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/_office/compute/workers", {"name": "y"}, token)
    check("the job credential does nothing else", s == 401, f"{s} {v}")
    s, v = call(office_url, "POST", f"/v1/_office/compute/leases/{lease}/complete", {}, w4_cred)
    check("the worker completes the job", s == 200, f"{s} {v}")
    s, v = call(office_url, "POST", f"/v1/_office/compute/leases/{lease}/complete", {}, w4_cred)
    check("completing again is harmless", s == 200, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/_office/compute/job/result", {"result": {"ok": False}}, token)
    check("the job credential dies with the lease", s == 401, f"{s} {v}")
    s, v = call(office_url, "POST", f"/v1/_office/compute/leases/{lease}/complete", {}, w2_cred)
    check("another worker cannot touch a lease it does not hold", s == 403, f"{s} {v}")


try:
    main()
finally:
    for p in procs:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            stop(p)
    if failed:
        for log in ("office.log", "worker1.log", "worker2.log"):
            path = os.path.join(work, log)
            if os.path.exists(path):
                print(f"--- {log} ---\n" + open(path).read()[-2000:])
    shutil.rmtree(work, ignore_errors=True)
if failed:
    sys.exit(f"{len(failed)} check(s) failed: " + ", ".join(failed))
print("\nall checks passed")
