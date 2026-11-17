#!/usr/bin/env python3
"""Durable events end to end, with real processes (T5.7).

Starts Office and two GardenX apps (orders, inventory), places orders as fast as it can,
and while it does, kills Office and then the consumer (inventory) with SIGKILL and starts
them again. When the dust settles the orders and the inventory must agree exactly: every
order has exactly one reservation, no reservation is without an order, nothing is left in
an outbox, nothing is dead, and each order's saga ran to the end.

usage: events.py <falak> <falak-office> <testdata/apps/gardenx> [office DATABASE_URL]
"""

import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import _http

FALAK, OFFICE_BIN, GARDENX = sys.argv[1], sys.argv[2], sys.argv[3]
OFFICE_DB = sys.argv[4] if len(sys.argv) > 4 else ""
ORDERS = int(os.environ.get("EVENTS_ORDERS", "120"))
PASSWORD = "correct horse battery staple 42"

work = tempfile.mkdtemp(prefix="falak-events-smoke-")
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


def call(base, method, path, body=None, token=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
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
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")
    except Exception as e:  # connection refused and the like
        return 0, str(e)


def wait_up(base, name, p):
    for _ in range(120):
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
    p = subprocess.Popen(argv, stdout=open(os.path.join(work, log), "a"), stderr=subprocess.STDOUT, env=e)
    procs.append(p)
    return p


def kill(p):
    """SIGKILL: no shutdown hooks, no flushing. This is the crash."""
    p.send_signal(signal.SIGKILL)
    p.wait(timeout=10)


def run(argv, env=None):
    e = dict(os.environ)
    e.pop("DATABASE_URL", None)
    e.update(env or {})
    r = subprocess.run(argv, capture_output=True, text=True, env=e)
    if r.returncode != 0:
        sys.exit(f"{' '.join(argv[:3])} failed: {r.stdout}{r.stderr}")
    return r.stdout


def scalar(db, sql):
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    try:
        return c.execute(sql).fetchone()[0]
    finally:
        c.close()


def column(db, sql):
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    try:
        return [r[0] for r in c.execute(sql).fetchall()]
    finally:
        c.close()


def main():
    office_port = port()
    office_url = f"http://127.0.0.1:{office_port}"
    data = os.path.join(work, "office")
    office_env = {"DATABASE_URL": OFFICE_DB} if OFFICE_DB else {}
    office_argv = [OFFICE_BIN, "serve", "--port", str(office_port), "--data", data, "--issuer", office_url]
    pw = {"OFFICE_PW": PASSWORD, **office_env}
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "admin@example.com",
         "--password-env", "OFFICE_PW", "--role", "office_admin"], pw)
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "shop@example.com",
         "--password-env", "OFFICE_PW"], pw)
    office = start(office_argv, "office.log", office_env)
    wait_up(office_url, "office", office)

    s, v = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    assert s == 200, (s, v)
    admin = v["access_token"]

    dirs, urls = {}, {}
    for name in ("orders", "inventory"):
        d = os.path.join(work, name)
        shutil.copytree(os.path.join(GARDENX, name), d, ignore=shutil.ignore_patterns(".falak"))
        s, v = call(office_url, "POST", "/v1/_office/enrollments", {"app": name, "tier": 1}, admin)
        check(f"an enrollment token for {name}", s == 201, f"{s} {v}")
        out = run([FALAK, "office", "enroll", d, "--office", office_url, "--token", v["token"], "--name", name])
        check(f"{name} enrolls", "enrolled" in out, out)
        dirs[name] = d
    s, v = call(office_url, "PUT", "/v1/_office/memberships",
                {"email": "shop@example.com", "app": "orders", "roles": []}, admin)
    check("the shop is a member of orders", s == 200, f"{s} {v}")

    env = {"FALAK_OFFICE_SYNC_SECS": "1", "FALAK_EVENTS_POLL_MS": "100"}
    ports = {n: port() for n in dirs}
    for name, d in dirs.items():
        urls[name] = f"http://127.0.0.1:{ports[name]}"

    def start_app(name):
        p = start([FALAK, "serve", d_of(name), "--port", str(ports[name])], f"{name}.log", env)
        wait_up(urls[name], name, p)
        return p

    def d_of(name):
        return dirs[name]

    apps = {n: start_app(n) for n in dirs}

    s, v = call(office_url, "POST", "/v1/auth/login", {"email": "shop@example.com", "password": PASSWORD})
    s, v = call(office_url, "POST", "/v1/_office/token", {"audience": "orders"}, v["access_token"])
    assert s == 200, (s, v)
    token = v["access_token"]

    # Wait for both contracts to be registered (the apps print it once they have).
    for _ in range(80):
        s, v = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
        logs_ok = all("contract registered" in open(os.path.join(work, f"{n}.log")).read() for n in dirs)
        if logs_ok:
            break
        time.sleep(0.25)
    check("both apps registered their event contracts", logs_ok)

    # A first order, end to end, before any trouble.
    s, o = call(urls["orders"], "POST", "/v1/purchases", {"sku": "rose", "qty": 1}, token)
    check("an order is accepted", s == 201, f"{s} {o}")
    odb = os.path.join(dirs["orders"], ".falak", "data.db")
    idb = os.path.join(dirs["inventory"], ".falak", "data.db")
    for _ in range(100):
        if scalar(idb, "SELECT COUNT(*) FROM reservations") == 1:
            break
        time.sleep(0.1)
    check("the order reaches inventory through Office", scalar(idb, "SELECT COUNT(*) FROM reservations") == 1)

    # Place orders while Office and then the consumer are killed and restarted.
    placed = []
    errors = []

    def place():
        for i in range(ORDERS):
            s, o = call(urls["orders"], "POST", "/v1/purchases", {"sku": "rose", "qty": 1 + i % 5}, token)
            if s == 201:
                placed.append(o["id"])
            else:
                errors.append((s, o))
            time.sleep(0.03)

    t = threading.Thread(target=place)
    t.start()
    time.sleep(0.6)
    kill(office)
    print("     killed Office")
    time.sleep(1.2)
    kill(apps["inventory"])
    print("     killed the consumer (inventory)")
    time.sleep(0.8)
    office = start(office_argv, "office.log", office_env)
    wait_up(office_url, "office", office)
    print("     restarted Office")
    time.sleep(0.8)
    apps["inventory"] = start_app("inventory")
    print("     restarted the consumer")
    # And once more, killing Office while it holds undelivered events.
    time.sleep(0.4)
    kill(office)
    print("     killed Office again")
    time.sleep(0.8)
    office = start(office_argv, "office.log", office_env)
    wait_up(office_url, "office", office)
    t.join()
    check("every order was accepted while the others were down", not errors and len(placed) == ORDERS, f"{len(placed)} placed, {errors[:2]}")

    total = ORDERS + 1
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            if (scalar(idb, "SELECT COUNT(*) FROM reservations") == total
                    and scalar(idb, "SELECT COUNT(*) FROM stock_moves") == total
                    and scalar(odb, "SELECT COUNT(*) FROM _falak_outbox WHERE sent_at IS NULL") == 0):
                break
        except sqlite3.Error:
            pass
        time.sleep(0.5)

    orders = scalar(odb, "SELECT COUNT(*) FROM purchases")
    reservations = scalar(idb, "SELECT COUNT(*) FROM reservations")
    check("the order count is exactly what was placed", orders == total, f"{orders} != {total}")
    check("inventory has exactly one reservation per order", reservations == total, f"{reservations} != {total}")
    order_ids = set(column(odb, "SELECT id FROM purchases"))
    refs = column(idb, "SELECT order_ref FROM reservations")
    check("no reservation is duplicated", len(refs) == len(set(refs)), f"{len(refs)} rows, {len(set(refs))} distinct")
    check("the reservations are for exactly the orders", set(refs) == order_ids, f"{len(set(refs) ^ order_ids)} differ")
    check("the inbox recorded each event once", scalar(idb, "SELECT COUNT(*) FROM _falak_inbox WHERE name = 'order_placed'") == total)
    check("nothing is left in the outbox", scalar(odb, "SELECT COUNT(*) FROM _falak_outbox WHERE sent_at IS NULL") == 0)

    # Sagas: one per order, each ran its step in inventory and completed.
    moves = scalar(idb, "SELECT COUNT(*) FROM stock_moves WHERE kind = 'confirmed'")
    check("every order's saga step ran in inventory", moves == total, f"{moves} != {total}")
    for _ in range(80):
        s, sagas = call(office_url, "GET", "/v1/_office/sagas", None, admin)
        done = (sagas or {}).get("counts", {}).get("completed", 0)
        if s == 200 and done >= total:
            break
        time.sleep(0.5)
    check("every saga completed", s == 200 and done == total, f"{done} of {total}: {(sagas or {}).get('counts')}")
    s, dead = call(office_url, "GET", "/v1/_office/events/dead", None, admin)
    check("no event is dead", s == 200 and dead["data"] == [], dead)

    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
    print()
    if failed:
        print(f"{len(failed)} check(s) failed; logs are in {work}")
        sys.exit(1)
    print("events smoke test passed")
    shutil.rmtree(work, ignore_errors=True)


try:
    main()
except SystemExit:
    raise
except BaseException:
    for p in procs:
        if p.poll() is None:
            p.kill()
    print(f"logs are in {work}")
    raise
finally:
    for p in procs:
        if p.poll() is None:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
