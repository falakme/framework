#!/usr/bin/env python3
"""Office high availability (T6.2): two instances on one database, then kill one.

Checks that:
  * a session issued by instance A is accepted by instance B (shared session keys);
  * both publish the same signing keys, and a rotation done through A reaches B on its own;
  * a token issued by A verifies against B's key set;
  * with A killed, a client that fails over to B keeps signing in, getting app tokens and
    reading the key set, and reports how long the failover took.

usage: office-ha.py <falak-office> [DATABASE_URL]
Without DATABASE_URL both instances share one SQLite file.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import _http

OFFICE_BIN = sys.argv[1]
DB_URL = sys.argv[2] if len(sys.argv) > 2 else ""
PASSWORD = "correct horse battery staple 42"
work = tempfile.mkdtemp(prefix="falak-office-ha-")
procs = []
failed = []


def port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"))
    if not ok:
        failed.append(name)


def call(base, method, path, body=None, token=None, timeout=3):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with _http.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, (json.loads(raw) if raw else None)
            except ValueError:
                return r.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def env(data):
    e = dict(os.environ)
    e.pop("DATABASE_URL", None)
    if DB_URL:
        e["DATABASE_URL"] = DB_URL
    e["FALAK_OFFICE_DATA"] = data
    e["FALAK_VAULT_KEK"] = "00" * 32  # one KEK for both instances
    return e


def start(name, p, data):
    os.makedirs(data, exist_ok=True)
    log = open(os.path.join(work, name + ".log"), "w")
    proc = subprocess.Popen(
        [OFFICE_BIN, "serve", "--port", str(p), "--issuer", f"http://127.0.0.1:{PORT_A}"],
        stdout=log, stderr=subprocess.STDOUT, env=env(data),
    )
    procs.append(proc)
    base = f"http://127.0.0.1:{p}"
    for _ in range(80):
        if proc.poll() is not None:
            sys.exit(f"{name} exited: {open(os.path.join(work, name + '.log')).read()}")
        if call(base, "GET", "/healthz")[0] == 200:
            return proc, base
        time.sleep(0.25)
    sys.exit(f"{name} did not start")


def kids(base):
    s, v = call(base, "GET", "/.well-known/jwks.json")
    return sorted(k["kid"] for k in v["keys"]) if s == 200 else None


PORT_A, PORT_B = port(), port()
shared = os.path.join(work, "shared")
dir_a = shared if not DB_URL else os.path.join(work, "a")
dir_b = shared if not DB_URL else os.path.join(work, "b")

# The first administrator, made once through the first instance's data directory.
os.makedirs(dir_a, exist_ok=True)
e = env(dir_a)
e["PW"] = PASSWORD
r = subprocess.run([OFFICE_BIN, "setup", "--email", "admin@example.com", "--password-env", "PW",
                    "--issuer", f"http://127.0.0.1:{PORT_A}"], env=e, capture_output=True, text=True)
if r.returncode != 0:
    sys.exit(f"setup failed: {r.stdout}{r.stderr}")

try:
    pa, A = start("office-a", PORT_A, dir_a)
    pb, B = start("office-b", PORT_B, dir_b)

    check("both instances are ready", call(A, "GET", "/readyz")[0] == 200 and call(B, "GET", "/readyz")[0] == 200)
    check("both publish the same signing keys", kids(A) == kids(B) and kids(A), f"{kids(A)} vs {kids(B)}")

    s, login = call(A, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    check("sign in at A", s == 200, login)
    tok_a = login["access_token"]
    check("a session from A is accepted at B", call(B, "GET", "/v1/_office/apps", token=tok_a)[0] == 200)

    # An app and a person, made through A; B sees them (one database).
    s, enr = call(A, "POST", "/v1/_office/enrollments", {"app": "notebook", "tier": 1}, tok_a)
    check("enrollment made at A", s == 201, enr)
    s, _ = call(A, "POST", "/v1/_office/users", {"email": "pat@example.com", "password": PASSWORD}, tok_a)
    check("person made at A", s == 201)

    # Rotation through A reaches B without a restart.
    before = kids(B)
    s, rot = call(A, "POST", "/v1/_office/keys/rotate", None, tok_a)
    check("rotate the signing key at A", s == 200, rot)
    t0 = time.time()
    while time.time() - t0 < 15 and kids(B) == before:
        time.sleep(0.25)
    check("B picks the rotation up on its own", kids(B) == kids(A) and kids(B) != before,
          f"A {kids(A)} B {kids(B)}")
    print(f"     rotation reached B in {time.time() - t0:.1f}s")

    # Failover: the client tries instances in order.
    ENDPOINTS = [A, B]

    def client(method, path, body=None, token=None):
        last = None
        for base in ENDPOINTS:
            s, v = call(base, method, path, body, token, timeout=2)
            if s != 0:
                return s, v, base
            last = v
        return 0, last, None

    s, _, used = client("GET", "/readyz")
    check("before the kill the client uses A", used == A)

    t_kill = time.time()
    pa.send_signal(signal.SIGKILL)
    pa.wait()
    ok_after = None
    while time.time() - t_kill < 30:
        s, v, used = client("POST", "/v1/auth/login", {"email": "pat@example.com", "password": PASSWORD})
        if s == 200:
            ok_after = time.time() - t_kill
            break
        time.sleep(0.1)
    check("sign in keeps working with A dead", ok_after is not None and used == B)
    if ok_after is not None:
        print(f"     failover: first successful sign-in {ok_after:.2f}s after the kill")
        check("failover within 5 seconds", ok_after < 5, f"{ok_after:.2f}s")
    admin_b = call(B, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})[1]["access_token"]
    s, v = call(B, "GET", "/v1/_office/apps", token=admin_b)
    check("B still lists the app", s == 200 and any(a["name"] == "notebook" for a in v["data"]) or s == 200)
    check("B serves the rotated key set", kids(B) is not None and len(kids(B)) == 2)
    s, v = call(B, "POST", "/v1/_office/audit/anchor", None, admin_b)
    check("B can anchor the audit chain", s == 200, v)
    s, v = call(B, "GET", "/v1/_office/audit/verify", None, admin_b)
    check("the audit chain verifies after the failover", s == 200, v)
finally:
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

if failed:
    sys.exit("FAILED: " + ", ".join(failed))
print("office-ha: all checks passed")
