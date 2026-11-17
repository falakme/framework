#!/usr/bin/env python3
"""Version 2 of Falak.me stores and returns the new `subtitle` field. Used by migrate-live.sh."""

import json
import sys
import urllib.request
import _http
import uuid

base = _http.base_url(sys.argv[1])


def call(method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("User-Agent", "falak-smoke/1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with _http.urlopen(req, timeout=15) as r:
        return r.status, json.loads(r.read())


email = f"v2-{uuid.uuid4().hex[:8]}@example.com"
password = "correct horse battery staple 42"
call("POST", "/v1/auth/signup", {"email": email, "password": password})
token = call("POST", "/v1/auth/login", {"email": email, "password": password})[1]["access_token"]
status, page = call("POST", "/v1/pages", {"slug": "v2", "title": "v2", "subtitle": "hello from version 2"}, token)
assert status == 201 and page["subtitle"] == "hello from version 2", page
status, body = call("GET", "/v1/pages", token=token)
assert any(r.get("subtitle") == "hello from version 2" for r in body["data"]), body
print("ok    version 2 stores and returns `subtitle`")
