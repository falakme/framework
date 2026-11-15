#!/usr/bin/env python3
"""`tenancy: database` on D1 (T3.9), against a deployed Worker.

  python3 tenant_db.py <url> signup           sign up a person, print their tenant id
  python3 tenant_db.py <url> check <tenant-a-email> ...   (see below)

Used by hand after `falak deploy` and `falak tenant add`; see TASKS.md.
"""

import base64
import json
import sys
import urllib.error
import urllib.request

PASSWORD = "correct horse battery staple 42"


def call(base, method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("User-Agent", "falak-smoke/1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else None)
        except ValueError:
            return e.code, None


def login(base, email):
    s, _ = call(base, "POST", "/v1/auth/signup", {"email": email, "password": PASSWORD})
    s, t = call(base, "POST", "/v1/auth/login", {"email": email, "password": PASSWORD})
    assert s == 200, (s, t)
    token = t["access_token"]
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return token, claims["tenant"]


if __name__ == "__main__":
    base, mode = sys.argv[1].rstrip("/"), sys.argv[2]
    if mode == "tenant":
        print(login(base, sys.argv[3])[1])
    elif mode == "use":
        token, tenant = login(base, sys.argv[3])
        s, row = call(base, "POST", "/v1/pages", {"slug": "mine", "title": "in my own database"}, token)
        print(sys.argv[3], tenant, "create:", s)
        s, body = call(base, "GET", "/v1/pages", token=token)
        print(sys.argv[3], "list:", s, [r["title"] for r in (body or {}).get("data", [])])
