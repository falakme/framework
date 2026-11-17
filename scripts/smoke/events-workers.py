#!/usr/bin/env python3
"""Durable events on the edge runtime (T5.7, the Workers half of the Phase 5 gate).

The same scenario as events.py, with the two GardenX apps (orders, inventory) deployed
as Workers with D1 databases on a real Cloudflare account, and Office running here behind
a Cloudflare quick tunnel (a Worker cannot reach this machine). Events move through the
edge relay: the after-write pass and the one-minute Cron Trigger.

Orders are placed while Office is killed with SIGKILL and restarted. Afterwards the order
and reservation counts must match exactly, with nothing dead and nothing left in the
outbox. There is no consumer process to kill on the edge: a Worker has no state outside
D1, and every request or cron pass is a fresh isolate.

    scripts/smoke/events-workers.py <falak> <falak-office> <examples/gardenx> [account id]

The account id defaults to CLOUDFLARE_ACCOUNT_ID. Log in with `wrangler login` or set
CLOUDFLARE_API_TOKEN. Needs `worker-build` and `npx` (for wrangler and cloudflared).
Every Worker, D1 database and the tunnel it creates are deleted at the end, even on
failure. If this machine cannot reach Cloudflare on port 7844 (cloudflared needs it),
start a tunnel some other way and set EVENTS_PUBLIC_URL and EVENTS_OFFICE_PORT.
EVENTS_ORDERS sets the number of orders (default 30).
"""

import json
import os
import re
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
import _http

FALAK, OFFICE_BIN, GARDENX = sys.argv[1:4]
ACCOUNT = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
if not ACCOUNT:
    sys.exit("pass the Cloudflare account id, or set CLOUDFLARE_ACCOUNT_ID")
ORDERS = int(os.environ.get("EVENTS_ORDERS", "30"))
PASSWORD = "correct horse battery staple 42"
PREFIX = "falak-t55"
NAMES = {n: f"{PREFIX}-{n}" for n in ("orders", "inventory")}
WRANGLER = ["npx", "--yes", "wrangler@4.156.2"]

work = tempfile.mkdtemp(prefix="falak-events-workers-")
procs, failed = [], []
env = {**os.environ, "CLOUDFLARE_ACCOUNT_ID": ACCOUNT}
env.pop("DATABASE_URL", None)
configs = {}


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"), flush=True)
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
        with _http.urlopen(req, timeout=30) as r:
            return r.status, parse(r.read())
    except urllib.error.HTTPError as e:
        return e.code, parse(e.read())
    except Exception as e:
        return 0, str(e)


def run(argv, extra=None, cwd=None):
    r = subprocess.run(argv, capture_output=True, text=True, env={**env, **(extra or {})}, cwd=cwd)
    if r.returncode != 0:
        sys.exit(f"{' '.join(argv[:4])} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def d1(app, sql):
    """Rows of a query against an app's remote D1 database."""
    for attempt in range(4):
        r = subprocess.run(
            WRANGLER + ["d1", "execute", f"{NAMES[app]}-db", "--remote", "--json", "--command", sql,
                        "--config", configs[app]],
            capture_output=True, text=True, env=env, cwd=work)
        out = r.stdout
        try:
            return json.loads(out[out.index("["):])[0]["results"]
        except (ValueError, KeyError, IndexError):
            time.sleep(2)
    raise RuntimeError(f"d1 query failed: {sql}\n{r.stdout}\n{r.stderr}")


def count(app, sql):
    return list(d1(app, sql)[0].values())[0]


def start_tunnel(port):
    log = os.path.join(work, "tunnel.log")
    p = subprocess.Popen(["npx", "--yes", "cloudflared", "tunnel", "--url", f"http://127.0.0.1:{port}"],
                         stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env)
    procs.append(p)
    for _ in range(120):
        m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", open(log).read())
        if m:
            return m.group(0)
        time.sleep(1)
    sys.exit("no tunnel address from cloudflared")


def main():
    public = os.environ.get("EVENTS_PUBLIC_URL", "")
    public = _http.base_url(public) if public else ""
    if public:  # a tunnel you started yourself, pointing at EVENTS_OFFICE_PORT
        port = int(os.environ.get("EVENTS_OFFICE_PORT", "18899"))
    else:
        port = free_port()
        print("starting a quick tunnel")
        public = start_tunnel(port)
    print("     Office is public at", public)
    data = os.path.join(work, "office")
    office_argv = [OFFICE_BIN, "serve", "--port", str(port), "--data", data, "--issuer", public]
    pw = {"OFFICE_PW": PASSWORD}
    for who, role in (("admin", ["--role", "office_admin"]), ("shop", [])):
        run([OFFICE_BIN, "user", "add", "--data", data, "--email", f"{who}@example.com",
             "--password-env", "OFFICE_PW", *role], pw)

    def start_office():
        p = subprocess.Popen(office_argv, stdout=open(os.path.join(work, "office.log"), "a"),
                             stderr=subprocess.STDOUT, env=env)
        procs.append(p)
        for _ in range(120):
            if call(public, "GET", "/healthz")[0] == 200:
                return p
            time.sleep(1)
        sys.exit("Office is not reachable at " + public)

    office = start_office()
    s, v = call(public, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    assert s == 200, (s, v)
    admin = v["access_token"]

    dirs = {}
    for name in NAMES:
        d = os.path.join(work, name)
        shutil.copytree(os.path.join(GARDENX, name), d, ignore=shutil.ignore_patterns(".falak"))
        s, v = call(public, "POST", "/v1/_office/enrollments", {"app": name, "tier": 1}, admin)
        check(f"an enrollment token for {name}", s == 201, f"{s} {v}")
        out = run([FALAK, "office", "enroll", d, "--office", public, "--token", v["token"], "--name", name])
        check(f"{name} enrolls", "enrolled" in out, out)
        dirs[name] = d
        configs[name] = os.path.join(d, ".falak", "edge", "wrangler.toml")
    s, v = call(public, "PUT", "/v1/_office/memberships",
                {"email": "shop@example.com", "app": "orders", "roles": []}, admin)
    check("the shop is a member of orders", s == 200, f"{s} {v}")

    urls = {}
    for name, d in dirs.items():
        print(f"deploying {name} (builds the Worker, a few minutes)", flush=True)
        out = run([FALAK, "deploy", d, "--account", ACCOUNT, "--name", NAMES[name]])
        m = re.search(r"https://\S+workers\.dev", out)
        check(f"{name} deploys to Workers", bool(m), out[-500:])
        urls[name] = m.group(0).rstrip("/")

    s, v = call(public, "POST", "/v1/auth/login", {"email": "shop@example.com", "password": PASSWORD})
    s, v = call(public, "POST", "/v1/_office/token", {"audience": "orders"}, v["access_token"])
    assert s == 200, (s, v)
    token = v["access_token"]

    # A first order, end to end, before any trouble.
    s = 0
    for _ in range(40):  # a new workers.dev address takes a moment
        s, o = call(urls["orders"], "POST", "/v1/purchases", {"sku": "rose", "qty": 1}, token)
        if s == 201:
            break
        time.sleep(3)
    check("an order is accepted by the orders Worker", s == 201, f"{s} {o}")
    got = 0
    for _ in range(60):  # after-write pass, or the next cron minute
        got = count("inventory", "SELECT COUNT(*) AS n FROM reservations")
        if got == 1:
            break
        time.sleep(5)
    check("the order reaches inventory through Office", got == 1, f"{got} reservations")

    # Orders while Office is killed and restarted (twice).
    placed, errors = [], []

    def place():
        for i in range(ORDERS):
            s, o = call(urls["orders"], "POST", "/v1/purchases", {"sku": "rose", "qty": 1 + i % 5}, token)
            if s == 201:
                placed.append(o["id"])
            else:
                errors.append((s, o))
            time.sleep(0.5)

    t = threading.Thread(target=place)
    t.start()
    time.sleep(4)
    office.send_signal(signal.SIGKILL)
    office.wait(timeout=10)
    print("     killed Office")
    time.sleep(8)
    office = start_office()
    print("     restarted Office")
    time.sleep(3)
    office.send_signal(signal.SIGKILL)
    office.wait(timeout=10)
    print("     killed Office again")
    time.sleep(5)
    office = start_office()
    print("     restarted Office again")
    t.join()
    check("every order was accepted while Office was down", not errors and len(placed) == ORDERS,
          f"{len(placed)} placed, {errors[:2]}")

    total = ORDERS + 1
    deadline = time.time() + 600
    while time.time() < deadline:
        try:
            if (count("inventory", "SELECT COUNT(*) AS n FROM reservations") == total
                    and count("inventory", "SELECT COUNT(*) AS n FROM stock_moves") == total
                    and count("orders", "SELECT COUNT(*) AS n FROM _falak_outbox WHERE sent_at IS NULL") == 0):
                break
        except RuntimeError:
            pass
        print("     waiting for the relay (cron runs every minute)", flush=True)
        time.sleep(20)

    orders = count("orders", "SELECT COUNT(*) AS n FROM purchases")
    reservations = count("inventory", "SELECT COUNT(*) AS n FROM reservations")
    check("the order count is exactly what was placed", orders == total, f"{orders} != {total}")
    check("inventory has exactly one reservation per order", reservations == total, f"{reservations} != {total}")
    order_ids = {r["id"] for r in d1("orders", "SELECT id FROM purchases")}
    refs = [r["order_ref"] for r in d1("inventory", "SELECT order_ref FROM reservations")]
    check("no reservation is duplicated", len(refs) == len(set(refs)), f"{len(refs)} rows, {len(set(refs))} distinct")
    check("the reservations are for exactly the orders", set(refs) == order_ids, f"{len(set(refs) ^ order_ids)} differ")
    inbox = count("inventory", "SELECT COUNT(*) AS n FROM _falak_inbox WHERE name = 'order_placed'")
    check("the inbox recorded each event once", inbox == total, f"{inbox} != {total}")
    left = count("orders", "SELECT COUNT(*) AS n FROM _falak_outbox WHERE sent_at IS NULL")
    check("nothing is left in the outbox", left == 0, f"{left} unsent")
    moves = count("inventory", "SELECT COUNT(*) AS n FROM stock_moves WHERE kind = 'confirmed'")
    check("every order's saga step ran in inventory", moves == total, f"{moves} != {total}")
    s, sagas = 0, None
    done = 0
    for _ in range(60):
        s, sagas = call(public, "GET", "/v1/_office/sagas", None, admin)
        done = (sagas or {}).get("counts", {}).get("completed", 0) if isinstance(sagas, dict) else 0
        if s == 200 and done >= total:
            break
        time.sleep(5)
    check("every saga completed", s == 200 and done == total,
          f"{done} of {total}: {(sagas or {}).get('counts') if isinstance(sagas, dict) else sagas}")
    s, dead = call(public, "GET", "/v1/_office/events/dead", None, admin)
    check("no event is dead", s == 200 and dead["data"] == [], dead)


def cleanup():
    for p in procs:
        if p.poll() is None:
            p.kill()
    for name in NAMES.values():
        for argv in (WRANGLER + ["delete", name, "--force"], WRANGLER + ["d1", "delete", f"{name}-db", "-y"]):
            # Run from the app's edge dir if it exists: wrangler needs a config to pick the Worker.
            subprocess.run(argv, capture_output=True, text=True, env=env, cwd=work)
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


ok = False
try:
    main()
    ok = not failed
except BaseException:
    print(f"logs are in {work}")
    raise
finally:
    cleanup()
    if ok:
        shutil.rmtree(work, ignore_errors=True)

if failed:
    sys.exit(f"{len(failed)} check(s) failed; logs are in {work}")
print("events workers smoke: all checks passed")
