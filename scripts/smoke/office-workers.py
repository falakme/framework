#!/usr/bin/env python3
"""A Worker enrolled with Office, against a real Cloudflare account (T4.6).

Office runs here. A public https address for it (a Cloudflare quick tunnel will do) is
needed because a Worker cannot reach this machine:

    npx cloudflared tunnel --url http://127.0.0.1:18899      # prints https://....trycloudflare.com

    scripts/smoke/office-workers.py <falak> <falak-office> <examples/notebook> \\
        <public https url of Office> <cloudflare account id> [port, default 18899]

It deploys a throwaway Worker and D1 database, checks sign-in once, revocation and what
a tier 2 app does when Office stops, and deletes both at the end.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import _http

FALAK, OFFICE_BIN, NOTEBOOK, PUBLIC, ACCOUNT = sys.argv[1:6]
PUBLIC = _http.base_url(PUBLIC)
PORT = int(sys.argv[6]) if len(sys.argv) > 6 else 18899
PASSWORD = "correct horse battery staple 42"
WORKER = "falak-t46-notebook"
STALENESS = 40

work = tempfile.mkdtemp(prefix="falak-office-workers-")
procs, failed = [], []
env = {**os.environ, "CLOUDFLARE_ACCOUNT_ID": ACCOUNT}
env.pop("DATABASE_URL", None)


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
    req.add_header("User-Agent", "falak-smoke/1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with _http.urlopen(req, timeout=20) as r:
            return r.status, parse(r.read())
    except urllib.error.HTTPError as e:
        return e.code, parse(e.read())
    except Exception as e:
        return 0, str(e)


def run(argv, extra=None):
    r = subprocess.run(argv, capture_output=True, text=True, env={**env, **(extra or {})})
    if r.returncode != 0:
        sys.exit(f"{' '.join(argv[:3])} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


def start_office():
    p = subprocess.Popen(
        [OFFICE_BIN, "serve", "--port", str(PORT), "--data", os.path.join(work, "office"), "--issuer", PUBLIC],
        stdout=open(os.path.join(work, "office.log"), "a"), stderr=subprocess.STDOUT, env=env)
    procs.append(p)
    for _ in range(120):
        if call(PUBLIC, "GET", "/healthz")[0] == 200:
            return p
        time.sleep(0.5)
    sys.exit("Office is not reachable at " + PUBLIC)


def stop(p):
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()


def main():
    pw = {"OFFICE_PW": PASSWORD}
    for who, role in (("admin", ["--role", "office_admin"]), ("alice", []), ("bob", [])):
        run([OFFICE_BIN, "user", "add", "--data", os.path.join(work, "office"), "--email", f"{who}@example.com",
             "--password-env", "OFFICE_PW", *role], pw)
    office = start_office()

    def login(who):
        s, v = call(PUBLIC, "POST", "/v1/auth/login", {"email": f"{who}@example.com", "password": PASSWORD})
        assert s == 200, (s, v)
        return v["access_token"]

    admin = login("admin")
    s, v = call(PUBLIC, "POST", "/v1/_office/enrollments", {"app": "notebook", "tier": 2}, admin)
    check("an enrollment token for a tier 2 app", s == 201, f"{s} {v}")
    d = os.path.join(work, "notebook")
    shutil.copytree(NOTEBOOK, d, ignore=shutil.ignore_patterns("web", ".falak", "node_modules"))
    run([FALAK, "office", "enroll", d, "--office", PUBLIC, "--token", v["token"], "--name", "notebook"])
    for who in ("alice", "bob"):
        s, v = call(PUBLIC, "PUT", "/v1/_office/memberships",
                    {"email": f"{who}@example.com", "app": "notebook", "roles": []}, admin)
        check(f"{who} is a member", s == 200, f"{s} {v}")

    print("deploying (this builds the Worker, a few minutes)")
    out = run([FALAK, "deploy", d, "--account", ACCOUNT, "--name", WORKER],
              {"FALAK_OFFICE_MAX_STALENESS": str(STALENESS)})
    m = re.search(r"https://\S+workers\.dev", out)
    check("the Worker deploys enrolled with Office", bool(m), out[-500:])
    url = m.group(0).rstrip("/")

    def app_token(who):
        s, v = call(PUBLIC, "POST", "/v1/_office/token", {"audience": "notebook"}, login(who))
        assert s == 200, (s, v)
        return v["access_token"]

    alice, bob = app_token("alice"), app_token("bob")
    s = 0
    for _ in range(40):  # a new workers.dev address takes a moment
        s, book = call(url, "POST", "/v1/notebooks", {"title": "from a Worker"}, alice)
        if s == 201:
            break
        time.sleep(3)
    check("the Worker accepts an Office token (key set fetched on the first request)", s == 201, f"{s} {book}")
    s, _ = call(url, "GET", "/v1/notebooks", token="not-a-token")
    check("it refuses a token that is not Office's", s == 401, s)
    s, page = call(url, "GET", "/v1/notebooks", token=bob)
    check("bob does not see alice's notebook", s == 200 and page["data"] == [], f"{s} {page}")
    s, _ = call(url, "POST", "/v1/auth/signup", {"email": "x@example.com", "password": PASSWORD})
    check("the Worker has no sign-up of its own", s in (404, 405), s)

    # Revocation: the Worker checks the feed on the request that comes after its interval.
    me = json.loads(__import__("base64").urlsafe_b64decode(alice.split(".")[1] + "==="))["sub"]
    s, v = call(PUBLIC, "POST", "/v1/_office/revocations", {"kind": "subject", "id": me}, admin)
    check("alice is revoked at Office", s == 201, f"{s} {v}")
    time.sleep(25)
    s, _ = call(url, "GET", "/v1/notebooks", token=alice)
    check("the Worker refuses her within its sync interval", s == 401, s)
    s, _ = call(url, "GET", "/v1/notebooks", token=bob)
    check("and still serves bob", s == 200, s)

    # Office stops. Tier 2: reads continue, writes pause after the staleness limit.
    stop(office)
    check("Office is down", call(PUBLIC, "GET", "/healthz")[0] != 200)
    time.sleep(STALENESS + 30)
    s, _ = call(url, "GET", "/v1/notebooks", token=bob)
    check("a tier 2 Worker still reads with Office down", s == 200, s)
    s, v = call(url, "POST", "/v1/notebooks", {"title": "paused"}, bob)
    check("and pauses writes after the staleness limit", s == 503, f"{s} {v}")

    office = start_office()
    time.sleep(2)
    s = 0
    for _ in range(10):
        s, v = call(url, "POST", "/v1/notebooks", {"title": "back"}, bob)
        if s == 201:
            break
        time.sleep(5)
    check("writes resume when Office returns", s == 201, f"{s} {v}")


def cleanup():
    for p in procs:
        if p.poll() is None:
            p.kill()
    for argv in (
        ["npx", "--yes", "wrangler@4", "delete", WORKER, "--force"],
        ["npx", "--yes", "wrangler@4", "d1", "delete", f"{WORKER}-db", "-y"],
    ):
        subprocess.run(argv, capture_output=True, text=True, env=env, cwd=work)
    shutil.rmtree(work, ignore_errors=True)


try:
    main()
finally:
    cleanup()

if failed:
    sys.exit(f"{len(failed)} check(s) failed")
print("office workers smoke: all checks passed")
