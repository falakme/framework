#!/usr/bin/env python3
"""Steady traffic against a running Falak.me, until a `stop` file appears next to the
output file. Writes `{requests, failures, slowest_ms}` as JSON. Used by migrate-live.sh."""

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

base, out = sys.argv[1].rstrip("/"), sys.argv[2]
stop = os.path.join(os.path.dirname(out), "stop")


def call(method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("User-Agent", "falak-traffic/1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


email = f"traffic-{uuid.uuid4().hex[:8]}@example.com"
password = "correct horse battery staple 42"
call("POST", "/v1/auth/signup", {"email": email, "password": password})
token = call("POST", "/v1/auth/login", {"email": email, "password": password})[1]["access_token"]

requests = failures = 0
slowest = 0.0
n = 0
while not os.path.exists(stop):
    n += 1
    started = time.time()
    try:
        if n % 3 == 0:
            status, _ = call(
                "POST", "/v1/pages",
                {"slug": f"p{n}-{uuid.uuid4().hex[:6]}", "title": f"page {n}", "status": "draft"},
                token,
            )
            ok = status == 201
        else:
            status, _ = call("GET", "/v1/pages", token=token)
            ok = status == 200
    except (urllib.error.URLError, OSError):
        ok = False
    requests += 1
    failures += 0 if ok else 1
    slowest = max(slowest, (time.time() - started) * 1000)
    time.sleep(0.02)

json.dump({"requests": requests, "failures": failures, "slowest_ms": round(slowest)}, open(out, "w"))
sys.exit(0)
