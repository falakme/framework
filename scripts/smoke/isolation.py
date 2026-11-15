#!/usr/bin/env python3
"""Isolation smoke test for Falak.me (T3.15).

Two people in two workspaces (tenants). Everything person A can try against person B's
data must fail: every endpoint of every entity, a level 2 query, forged identity, and
smuggled fields. Then B's data is checked to be untouched.

  python3 scripts/smoke/isolation.py http://127.0.0.1:8787

Exit code 0 means every check held.
"""

import json
import sys
import urllib.error
import urllib.request
import uuid

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8787"
PASSWORD = "correct horse battery staple 42"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f"  ({detail})"))
    if not ok:
        failures += 1


def call(method, path, body=None, token=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("User-Agent", "falak-smoke/1")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, (json.loads(raw) if raw else None)
        except ValueError:
            return error.code, None


def person(label):
    email = f"{label}-{uuid.uuid4().hex[:10]}@example.com"
    status, body = call("POST", "/v1/auth/signup", {"email": email, "password": PASSWORD})
    assert status == 201, (status, body)
    status, tokens = call("POST", "/v1/auth/login", {"email": email, "password": PASSWORD})
    assert status == 200, (status, tokens)
    return tokens["access_token"]


def create(token, path, body):
    status, row = call("POST", path, body, token)
    assert status == 201, (path, status, row)
    return row


def main():
    a, b = person("alice"), person("bob")

    # --- Both people fill their own workspace. The same slug is fine in two workspaces.
    a_profile = create(a, "/v1/profiles", {"display_name": "Alice", "bio": "alice private bio"})
    b_profile = create(b, "/v1/profiles", {"display_name": "Bob", "bio": "bob private bio"})
    a_draft = create(a, "/v1/pages", {"slug": "home", "title": "Alice home", "body": "a draft", "status": "draft"})
    a_pub = create(a, "/v1/pages", {"slug": "news", "title": "Alice news", "body": "a news", "status": "published"})
    b_draft = create(b, "/v1/pages", {"slug": "home", "title": "Bob home", "body": "b draft", "status": "draft"})
    b_pub = create(b, "/v1/pages", {"slug": "news", "title": "Bob news", "body": "b news", "status": "published"})
    a_asset = create(a, "/v1/assets", {"name": "a.png", "content_type": "image/png", "size_bytes": 10, "file_id": str(uuid.uuid4())})
    b_asset = create(b, "/v1/assets", {"name": "b.png", "content_type": "image/png", "size_bytes": 20, "file_id": str(uuid.uuid4())})
    check("the same slug can exist in two workspaces", a_draft["slug"] == b_draft["slug"] == "home")

    theirs = {
        "profiles": [b_profile["id"]],
        "pages": [b_draft["id"], b_pub["id"]],
        "assets": [b_asset["id"]],
    }
    ours = {"profiles": a_profile["id"], "pages": a_pub["id"], "assets": a_asset["id"]}

    # --- Every endpoint, aimed at B's rows, as A.
    for entity, ids in theirs.items():
        for rid in ids:
            tag = f"{entity}/{rid[:8]}"
            status, _ = call("GET", f"/v1/{entity}/{rid}", token=a)
            check(f"A cannot read {tag}", status == 404, status)
            status, _ = call("PATCH", f"/v1/{entity}/{rid}", {"display_name": "x", "title": "x", "name": "x"}, a)
            check(f"A cannot update {tag}", status in (404, 400), status)
            status, _ = call("PUT", f"/v1/{entity}/{rid}", {"display_name": "x", "title": "x", "name": "x"}, a)
            check(f"A cannot replace {tag}", status in (404, 400), status)
            status, _ = call("DELETE", f"/v1/{entity}/{rid}", token=a)
            check(f"A cannot delete {tag}", status == 404, status)
    for rid in theirs["pages"]:
        status, _ = call("POST", f"/v1/pages/{rid}/publish_page", {"id": rid}, a)
        check(f"A cannot run publish_page on {rid[:8]}", status == 404, status)

    # --- Lists and filters show only A's rows.
    for entity, mine in ours.items():
        status, body = call("GET", f"/v1/{entity}", token=a)
        ids = [r["id"] for r in (body or {}).get("data", [])]
        check(f"A's {entity} list holds only A's rows", status == 200 and mine in ids and not set(ids) & set(theirs[entity]), ids)
        for rid in theirs[entity]:
            status, body = call("GET", f"/v1/{entity}?filter[id]={rid}", token=a)
            rows = (body or {}).get("data", []) if status == 200 else []
            check(f"filtering {entity} by B's id finds nothing", rows == [], (status, body))
    status, body = call("GET", "/v1/profiles", token=a)
    bobs = [r for r in body["data"] if r["id"] == b_profile["id"]]
    check("B's profile is not in A's directory", bobs == [], body)

    # --- The level 2 query reads through the same walls.
    status, body = call("GET", "/v1/_queries/published_pages?prefix=%25", token=a)
    slugs = [(r["slug"], r["title"]) for r in (body or {}).get("data", [])]
    check("the query returns A's published page only", status == 200 and slugs == [("news", "Alice news")], (status, slugs))
    status, body = call("GET", "/v1/_queries/published_pages?prefix=%25&sql=SELECT%201", token=a)
    check("the query takes no SQL from the request", status == 400, status)
    status, body = call("GET", "/v1/_queries/published_pages?prefix=x%27%20OR%20%271%27%3D%271", token=a)
    check("an injection attempt in a parameter is only a value", status == 200 and body["data"] == [], (status, body))

    # --- Smuggled and forged identity.
    for field in ("tenant_id", "owner_id"):
        status, _ = call("POST", "/v1/pages", {"slug": "x", "title": "x", field: str(uuid.uuid4())}, a)
        check(f"A cannot supply `{field}` on create", status == 400, status)
    forged = {"X-Tenant-Id": "00000000-0000-0000-0000-0000000000b2", "X-User-Id": b_profile["owner_id"], "X-Falak-Subject": b_profile["owner_id"]}
    status, body = call("GET", "/v1/pages", token=a, headers=forged)
    ids = [r["id"] for r in (body or {}).get("data", [])]
    check("tenant and user headers are ignored", status == 200 and not set(ids) & set(theirs["pages"]), (status, ids))
    status, _ = call("GET", "/v1/pages")
    check("no token is refused", status == 401, status)
    status, _ = call("GET", "/v1/pages", token=a[:-3] + "AAA")
    check("a damaged token is refused", status == 401, status)

    # --- B's data is exactly as it was.
    status, body = call("GET", "/v1/pages", token=b)
    rows = {r["id"]: r for r in body["data"]}
    check("B still has both pages", set(rows) == set(theirs["pages"]), list(rows))
    check("B's pages are unchanged", rows[b_draft["id"]]["title"] == "Bob home" and rows[b_draft["id"]]["status"] == "draft", rows)
    status, row = call("GET", f"/v1/profiles/{b_profile['id']}", token=b)
    check("B's profile is unchanged", status == 200 and row["display_name"] == "Bob" and row["bio"] == "bob private bio", row)
    status, row = call("GET", f"/v1/assets/{b_asset['id']}", token=b)
    check("B's file record is unchanged", status == 200 and row["name"] == "b.png", row)

    print()
    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("all isolation checks held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
