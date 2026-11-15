#!/usr/bin/env python3
"""Falak Office end to end, with real processes (T4.13).

Starts Office and two apps (Notebook at tier 1, a copy of it named `journal` at tier 2),
enrolls them, and checks: sign in once, a token per app, no sign-up on an app, revocation
reaching the apps, key rotation under load with no failed request, and what each tier does
when Office stops.

usage: office.py <falak> <falak-office> <examples/notebook> [office DATABASE_URL]
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

FALAK, OFFICE_BIN, NOTEBOOK = sys.argv[1], sys.argv[2], sys.argv[3]
OFFICE_DB = sys.argv[4] if len(sys.argv) > 4 else ""
PASSWORD = "correct horse battery staple 42"
STALENESS = 5  # seconds; the apps' limit before tier 2 goes read only
SYNC = 1

work = tempfile.mkdtemp(prefix="falak-office-smoke-")
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


def parse(raw):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return raw.decode(errors="replace")


def call(base, method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, parse(r.read())
    except urllib.error.HTTPError as e:
        return e.code, parse(e.read())
    except Exception as e:  # connection refused and the like
        return 0, str(e)


def wait_up(base, name, p):
    for _ in range(80):
        if p.poll() is not None:
            break
        if call(base, "GET", "/healthz")[0] == 200:
            return
        time.sleep(0.25)
    sys.exit(f"{name} did not start")


def start(argv, log, env=None):
    e = dict(os.environ)
    e.pop("DATABASE_URL", None)
    e.update(env or {})
    p = subprocess.Popen(argv, stdout=open(os.path.join(work, log), "w"), stderr=subprocess.STDOUT, env=e)
    procs.append(p)
    return p


def stop(p):
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()


def run(argv, env=None):
    e = dict(os.environ)
    e.pop("DATABASE_URL", None)
    e.update(env or {})
    r = subprocess.run(argv, capture_output=True, text=True, env=e)
    if r.returncode != 0:
        sys.exit(f"{' '.join(argv[:3])} failed: {r.stdout}{r.stderr}")
    return r.stdout


def main():
    office_port = port()
    office_url = f"http://127.0.0.1:{office_port}"
    data = os.path.join(work, "office")
    office_env = {"DATABASE_URL": OFFICE_DB} if OFFICE_DB else {}
    office_argv = [OFFICE_BIN, "serve", "--port", str(office_port), "--data", data, "--issuer", office_url]

    # Accounts are made by an administrator.
    pw = {"OFFICE_PW": PASSWORD, **office_env}
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "admin@example.com",
         "--password-env", "OFFICE_PW", "--role", "office_admin"], pw)
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "alice@example.com",
         "--password-env", "OFFICE_PW"], pw)
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "bob@example.com",
         "--password-env", "OFFICE_PW"], pw)

    office = start(office_argv, "office.log", office_env)
    wait_up(office_url, "office", office)

    s, v = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    check("the administrator signs in", s == 200, f"{s} {v}")
    admin = v["access_token"]
    s, v = call(office_url, "POST", "/v1/auth/signup", {"email": "x@example.com", "password": PASSWORD})
    check("Office has no self sign-up", s == 404, s)

    # Two apps, enrolled with one-time tokens.
    apps = {}
    for name, tier in (("notebook", 1), ("journal", 2)):
        d = os.path.join(work, name)
        shutil.copytree(NOTEBOOK, d, ignore=shutil.ignore_patterns("web", ".falak", "node_modules"))
        if name != "notebook":
            path = os.path.join(d, "app.yaml")
            text = open(path).read().replace("name: notebook", f"name: {name}")
            open(path, "w").write(text)
        s, v = call(office_url, "POST", "/v1/_office/enrollments", {"app": name, "tier": tier}, admin)
        check(f"an enrollment token for {name} (tier {tier})", s == 201, f"{s} {v}")
        out = run([FALAK, "office", "enroll", d, "--office", office_url, "--token", v["token"], "--name", name])
        check(f"{name} enrolls", "enrolled" in out, out)
        r = subprocess.run([FALAK, "office", "enroll", d, "--office", office_url, "--token", v["token"], "--name", name],
                           capture_output=True, text=True)
        check(f"{name} cannot enroll twice", r.returncode != 0)
        status = run([FALAK, "office", "status", d])
        check(f"{name} reports the link", "link:      ok" in status, status)
        apps[name] = d

    # Alice and Bob are members of both apps.
    for who in ("alice", "bob"):
        for name in apps:
            s, v = call(office_url, "PUT", "/v1/_office/memberships",
                        {"email": f"{who}@example.com", "app": name, "roles": []}, admin)
            check(f"{who} is a member of {name}", s == 200, f"{s} {v}")

    env = {"FALAK_OFFICE_SYNC_SECS": str(SYNC), "FALAK_OFFICE_MAX_STALENESS": str(STALENESS)}
    urls = {}
    for name, d in apps.items():
        p = port()
        urls[name] = f"http://127.0.0.1:{p}"
        proc = start([FALAK, "serve", d, "--port", str(p)], f"{name}.log", env)
        wait_up(urls[name], name, proc)

    # Sign in once; a token for each app.
    def session(email):
        s, v = call(office_url, "POST", "/v1/auth/login", {"email": email, "password": PASSWORD})
        assert s == 200, (s, v)
        return v["access_token"]

    def app_token(sess, name):
        s, v = call(office_url, "POST", "/v1/_office/token", {"audience": name}, sess)
        assert s == 200, (s, v)
        return v["access_token"]

    alice = session("alice@example.com")
    bob = session("bob@example.com")
    t_nb, t_jr = app_token(alice, "notebook"), app_token(alice, "journal")
    b_nb = app_token(bob, "notebook")
    check("one sign-in gives a token for each app", bool(t_nb and t_jr))

    s, book = call(urls["notebook"], "POST", "/v1/notebooks", {"title": "Alice's"}, t_nb)
    check("notebook accepts alice's Office token", s == 201, f"{s} {book}")
    s, book2 = call(urls["journal"], "POST", "/v1/notebooks", {"title": "Alice's journal"}, t_jr)
    check("journal accepts alice's Office token", s == 201, f"{s} {book2}")
    s, _ = call(urls["journal"], "GET", "/v1/notebooks", token=t_nb)
    check("a token for one app is refused by the other (audience)", s == 401, s)
    s, page = call(urls["notebook"], "GET", "/v1/notebooks", token=b_nb)
    check("bob does not see alice's notebooks", s == 200 and page["data"] == [], f"{s} {page}")
    s, _ = call(urls["notebook"], "POST", "/v1/auth/signup", {"email": "z@example.com", "password": PASSWORD})
    check("an enrolled app has no sign-up of its own", s in (404, 405), s)
    s, _ = call(urls["notebook"], "GET", "/v1/notebooks", token=session("alice@example.com"))
    check("an Office session token is not an app token", s == 401, s)

    # Revocation reaches the apps.
    from_jti = app_token(alice, "notebook")
    s, _ = call(urls["notebook"], "GET", "/v1/notebooks", token=from_jti)
    check("a fresh token works", s == 200, s)
    s, v = call(office_url, "POST", "/v1/_office/revocations", {"kind": "subject", "id": subject_of(from_jti)}, admin)
    check("an administrator revokes a person", s == 201, f"{s} {v}")
    time.sleep(SYNC * 3)
    s, _ = call(urls["notebook"], "GET", "/v1/notebooks", token=from_jti)
    check("the revocation reaches the app within seconds", s == 401, s)
    s, _ = call(urls["notebook"], "GET", "/v1/notebooks", token=b_nb)
    check("other people are not affected", s == 200, s)

    # Rotate the signing key while requests flow.
    stats = {"n": 0, "bad": []}
    stopping = threading.Event()

    def traffic():
        sess = session("bob@example.com")
        while not stopping.is_set():
            for name in ("notebook", "journal"):
                tok = app_token(sess, name)
                s, _ = call(urls[name], "GET", "/v1/notebooks", token=tok)
                stats["n"] += 1
                if s != 200:
                    stats["bad"].append((name, s))
            time.sleep(0.02)

    th = threading.Thread(target=traffic)
    th.start()
    time.sleep(1)
    out = run([FALAK, "office", "rotate-key", "--office", office_url, "--email", "admin@example.com",
               "--password-env", "OFFICE_PW"], {"OFFICE_PW": PASSWORD})
    check("Office rotates its signing key", '"kid"' in out, out)
    time.sleep(3)
    stopping.set()
    th.join()
    check("no request failed while the key rotated", stats["n"] > 20 and not stats["bad"],
          f"{stats['n']} requests, failures {stats['bad'][:5]}")
    s, jwks = call(office_url, "GET", "/.well-known/jwks.json")
    check("both keys are published after a rotation", s == 200 and len(jwks["keys"]) == 2, jwks)
    check("a token signed with the old key still works", call(urls["notebook"], "GET", "/v1/notebooks", token=b_nb)[0] == 200)
    out = run([FALAK, "office", "rotate-key", "--office", office_url, "--email", "admin@example.com",
               "--password-env", "OFFICE_PW", "--retire"], {"OFFICE_PW": PASSWORD})
    s, jwks = call(office_url, "GET", "/.well-known/jwks.json")
    check("retiring drops the old key", s == 200 and len(jwks["keys"]) == 1, jwks)
    time.sleep(SYNC * 2)
    fresh = app_token(bob, "notebook")
    check("a token under the new key works", call(urls["notebook"], "GET", "/v1/notebooks", token=fresh)[0] == 200)

    # Office stops.
    tok_nb, tok_jr = app_token(bob, "notebook"), app_token(bob, "journal")
    stop(office)
    check("Office is down", call(office_url, "GET", "/healthz")[0] == 0)
    time.sleep(STALENESS + SYNC + 2)
    s, _ = call(urls["notebook"], "POST", "/v1/notebooks", {"title": "while Office is down"}, tok_nb)
    check("tier 1 keeps working with Office down", s == 201, s)
    s, _ = call(urls["journal"], "GET", "/v1/notebooks", token=tok_jr)
    check("tier 2 still reads with Office down", s == 200, s)
    s, v = call(urls["journal"], "POST", "/v1/notebooks", {"title": "paused"}, tok_jr)
    check("tier 2 pauses writes after the limit", s == 503, f"{s} {v}")
    s, _ = call(urls["journal"], "GET", "/healthz")
    check("the app itself stays up", s == 200, s)

    # Office returns.
    office = start(office_argv, "office2.log", office_env)
    wait_up(office_url, "office", office)
    time.sleep(SYNC * 3)
    s, v = call(urls["journal"], "POST", "/v1/notebooks", {"title": "back"}, tok_jr)
    check("tier 2 writes again once Office is back", s == 201, f"{s} {v}")


def subject_of(token):
    import base64
    body = token.split(".")[1]
    body += "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(body))["sub"]


ok_run = False
try:
    main()
    ok_run = True
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    if failed or not ok_run:
        for n in ("office", "office2", "notebook", "journal"):
            path = os.path.join(work, n + ".log")
            if os.path.exists(path):
                print(f"--- {n}.log\n" + open(path).read()[-1500:])
    shutil.rmtree(work, ignore_errors=True)

if failed:
    sys.exit(f"{len(failed)} check(s) failed")
print("office smoke: all checks passed")
