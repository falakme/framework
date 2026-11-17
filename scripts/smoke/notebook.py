#!/usr/bin/env python3
"""Notebook smoke test (T1.17): two users, and each sees only their own data.

Talks to a running server over HTTP using only the standard library. Usage:

    notebook.py http://127.0.0.1:8787

Exits 0 if every check passes, 1 otherwise, and prints one line per check.
"""

import json
import sys
import urllib.error
import urllib.request
import _http
import uuid

BASE = _http.base_url(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787")
PASSWORD = "correct horse battery"
failures = []


def call(method, path, body=None, token=None, headers=None):
    """Return (status, parsed JSON or None, response headers)."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    # Cloudflare refuses Python's default user agent (error 1010) on workers.dev.
    request.add_header("User-Agent", "falak-smoke/1")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with _http.urlopen(request, timeout=20) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None), response.headers
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return error.code, parsed, error.headers


def check(name, condition, detail=""):
    print(("ok    " if condition else "FAIL  ") + name + ("" if condition else f"  ({detail})"))
    if not condition:
        failures.append(name)


def sign_up_and_in(email):
    status, body, _ = call("POST", "/v1/auth/signup", {"email": email, "password": PASSWORD})
    check(f"sign up {email}", status == 201 and body and "id" in body, f"{status} {body}")
    status, body, _ = call("POST", "/v1/auth/login", {"email": email, "password": PASSWORD})
    check(f"log in {email}", status == 200 and body and "access_token" in body, f"{status} {body}")
    return body["access_token"], body["refresh_token"]


def main():
    run = uuid.uuid4().hex[:8]
    alice, alice_refresh = sign_up_and_in(f"alice-{run}@example.com")
    bob, _ = sign_up_and_in(f"bob-{run}@example.com")

    # Each user creates a notebook and a note.
    status, a_book, headers = call("POST", "/v1/notebooks", {"title": "Alice's book"}, alice)
    check("alice creates a notebook", status == 201 and a_book, f"{status} {a_book}")
    check("the response carries an ETag", bool(headers.get("ETag")))
    status, b_book, _ = call("POST", "/v1/notebooks", {"title": "Bob's book"}, bob)
    check("bob creates a notebook", status == 201 and b_book, f"{status} {b_book}")
    status, a_note, _ = call(
        "POST", "/v1/notes", {"title": "Alice note", "notebook_id": a_book["id"]}, alice
    )
    check("alice creates a note", status == 201 and a_note, f"{status} {a_note}")
    status, b_note, _ = call(
        "POST", "/v1/notes", {"title": "Bob note", "notebook_id": b_book["id"]}, bob
    )
    check("bob creates a note", status == 201 and b_note, f"{status} {b_note}")

    # Each sees only their own.
    status, page, _ = call("GET", "/v1/notes", token=alice)
    titles = [n["title"] for n in (page or {}).get("data", [])]
    check("alice lists only her own notes", status == 200 and titles == ["Alice note"], f"{status} {titles}")
    status, page, _ = call("GET", "/v1/notes", token=bob)
    titles = [n["title"] for n in (page or {}).get("data", [])]
    check("bob lists only his own notes", status == 200 and titles == ["Bob note"], f"{status} {titles}")

    # The wrong-user checks: 404, never 403, and nothing changes.
    status, _, _ = call("GET", f"/v1/notes/{a_note['id']}", token=bob)
    check("bob cannot read alice's note (404)", status == 404, status)
    status, _, _ = call(
        "PATCH", f"/v1/notes/{a_note['id']}", {"title": "hacked"}, bob, {"If-Match": f'W/"{a_note["version"]}"'}
    )
    check("bob cannot update alice's note (404)", status == 404, status)
    status, _, _ = call("DELETE", f"/v1/notes/{a_note['id']}", token=bob)
    check("bob cannot delete alice's note (404)", status == 404, status)
    status, _, _ = call("POST", f"/v1/notes/{a_note['id']}/archive_note", {}, bob)
    check("bob cannot run a command on alice's note (404)", status == 404, status)
    status, still, _ = call("GET", f"/v1/notes/{a_note['id']}", token=alice)
    check(
        "alice's note is unchanged",
        status == 200 and still["title"] == "Alice note" and still["archived"] in (False, 0, None),
        f"{status} {still}",
    )

    # Identity comes only from the token.
    status, _, _ = call("GET", "/v1/notes")
    check("no token is refused (401)", status == 401, status)
    status, _, _ = call("GET", "/v1/notes", token=str(uuid.uuid4()))
    check("a made-up bearer value is refused (401)", status == 401, status)
    status, _, _ = call("GET", "/v1/notes", token="sub:" + a_note["owner_id"])
    check("a forged 'sub:' token is refused (401)", status == 401, status)
    status, page, _ = call(
        "GET", "/v1/notes", token=bob, headers={"X-User-Id": a_note["owner_id"], "X-Falak-Subject": a_note["owner_id"]}
    )
    titles = [n["title"] for n in (page or {}).get("data", [])]
    check("user-id headers are ignored", status == 200 and titles == ["Bob note"], f"{status} {titles}")
    head, tail = alice.rsplit(".", 1)
    status, _, _ = call("GET", "/v1/notes", token=head + "." + tail[:-2] + ("AA" if tail[-2:] != "AA" else "BB"))
    check("a token with a damaged signature is refused (401)", status == 401, status)

    # The owner is set by the server.
    status, _, _ = call(
        "POST",
        "/v1/notes",
        {"title": "x", "notebook_id": a_book["id"], "owner_id": a_note["owner_id"]},
        bob,
    )
    check("a client-supplied owner is rejected (400)", status == 400, status)

    # Optimistic locking and idempotency.
    status, updated, _ = call(
        "PATCH", f"/v1/notes/{a_note['id']}", {"title": "Alice note v2"}, alice, {"If-Match": f'W/"{a_note["version"]}"'}
    )
    check("alice updates her note with If-Match", status == 200 and updated["version"] == a_note["version"] + 1, f"{status} {updated}")
    status, _, _ = call(
        "PATCH", f"/v1/notes/{a_note['id']}", {"title": "stale"}, alice, {"If-Match": f'W/"{a_note["version"]}"'}
    )
    check("a stale If-Match is refused (412)", status == 412, status)
    key = {"Idempotency-Key": str(uuid.uuid4())}
    s1, first, _ = call("POST", "/v1/notes", {"title": "once", "notebook_id": a_book["id"]}, alice, key)
    s2, second, h2 = call("POST", "/v1/notes", {"title": "once", "notebook_id": a_book["id"]}, alice, key)
    check(
        "the same idempotency key returns the first result",
        s1 == 201 and s2 == 201 and first["id"] == second["id"] and h2.get("Idempotent-Replayed") == "true",
        f"{s1} {s2}",
    )
    s3, _, _ = call("POST", "/v1/notes", {"title": "different", "notebook_id": a_book["id"]}, alice, key)
    check("the same key with a different body is refused (422)", s3 == 422, s3)

    # A command, and sessions.
    status, archived, _ = call("POST", f"/v1/notes/{a_note['id']}/archive_note", {}, alice)
    check("alice runs archive_note", status == 200 and archived["archived"] in (True, 1), f"{status} {archived}")

    status, refreshed, _ = call("POST", "/v1/auth/refresh", {"refresh_token": alice_refresh})
    check("refresh gives new tokens", status == 200 and "access_token" in (refreshed or {}), f"{status}")
    status, _, _ = call("POST", "/v1/auth/refresh", {"refresh_token": alice_refresh})
    check("the old refresh token no longer works (401)", status == 401, status)

    status, body, _ = call("POST", "/v1/auth/login", {"email": f"nobody-{run}@example.com", "password": PASSWORD})
    status2, body2, _ = call("POST", "/v1/auth/login", {"email": f"alice-{run}@example.com", "password": "wrong wrong wrong"})
    check(
        "unknown email and wrong password give the same answer",
        status == status2 == 401 and (body or {}).get("code") == (body2 or {}).get("code"),
        f"{status} {status2}",
    )

    print()
    if failures:
        print(f"{len(failures)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
