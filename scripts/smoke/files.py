#!/usr/bin/env python3
"""File uploads end to end over HTTP, against a server started with FALAK_S3_* set (T3.11).

Two people in two workspaces. A uploads a picture straight to the store with the
presigned URL, completes it, and downloads it. Everything B tries on A's file fails. A
file that is not what it claims to be is refused and removed.

  python3 scripts/smoke/files.py http://127.0.0.1:8787
"""

import json
import sys
import urllib.error
import urllib.request
import uuid

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8787"
PASSWORD = "correct horse battery staple 42"
PNG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + bytes(range(40))
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f"  ({detail})"))
    failures += 0 if ok else 1


def call(method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
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


def person(label):
    email = f"{label}-{uuid.uuid4().hex[:10]}@example.com"
    call("POST", "/v1/auth/signup", {"email": email, "password": PASSWORD})
    return call("POST", "/v1/auth/login", {"email": email, "password": PASSWORD})[1]["access_token"]


def upload(token, data, content_type, name="photo.png"):
    s, v = call("POST", "/v1/_files", {"name": name, "content_type": content_type, "size": len(data)}, token)
    assert s == 201, (s, v)
    up = v["upload"]
    req = urllib.request.Request(up["url"], data=data, method="PUT")
    for k, val in up["headers"].items():
        req.add_header(k, val)
    with urllib.request.urlopen(req, timeout=30) as r:
        assert r.status == 200, r.status
    return v["id"]


def main():
    a, b = person("alice"), person("bob")

    fid = upload(a, PNG, "image/png")
    s, v = call("GET", f"/v1/_files/{fid}", token=a)
    check("a file cannot be downloaded before it is checked", s == 404, (s, v))
    s, v = call("POST", f"/v1/_files/{fid}/complete", token=a)
    check("a good file is checked and published", s == 200 and v["state"] == "clean", (s, v))
    s, v = call("GET", f"/v1/_files/{fid}", token=a)
    check("the owner gets a download URL", s == 200 and "download" in v, (s, v))
    with urllib.request.urlopen(v["download"]["url"], timeout=30) as r:
        body = r.read()
        disp = r.headers.get("content-disposition", "")
    check("the download is the same bytes, as an attachment", body == PNG and disp.startswith("attachment"), (len(body), disp))

    for what, method, path in [
        ("download", "GET", f"/v1/_files/{fid}"),
        ("complete", "POST", f"/v1/_files/{fid}/complete"),
    ]:
        s, _ = call(method, path, token=b)
        check(f"B cannot {what} A's file", s == 404, s)
    s, _ = call("GET", f"/v1/_files/{fid}")
    check("no token is refused", s == 401, s)

    exe = b"MZ\x90\x00 an executable pretending to be a picture"
    bad = upload(a, exe, "image/png", "evil.png")
    s, v = call("POST", f"/v1/_files/{bad}/complete", token=a)
    check("a file that is not what it says is refused", s == 400 and v["code"] == "file_content_mismatch", (s, v))
    s, _ = call("GET", f"/v1/_files/{bad}", token=a)
    check("and is never served", s == 404, s)

    for body in [
        {"name": "x.html", "content_type": "text/html", "size": 10},
        {"name": "x.png", "content_type": "image/png", "size": 10**9},
    ]:
        s, _ = call("POST", "/v1/_files", body, a)
        check(f"refused before any URL exists: {body['content_type']} {body['size']}", s == 400, s)

    print()
    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("all file checks held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
