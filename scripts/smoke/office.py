#!/usr/bin/env python3
"""Falak Office end to end, with real processes (T4.13).

Starts Office and two apps (Notebook at tier 1, a copy of it named `journal` at tier 2),
enrolls them, and checks: sign in once, a token per app, no sign-up on an app, revocation
reaching the apps, key rotation under load with no failed request, and what each tier does
when Office stops.

usage: office.py <falak> <falak-office> <examples/notebook> <falak-studio> [office DATABASE_URL]
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
import _http
import uuid

FALAK, OFFICE_BIN, NOTEBOOK = sys.argv[1], sys.argv[2], sys.argv[3]
ROOT = os.path.dirname(os.path.dirname(NOTEBOOK))
ACADEMY = os.path.join(ROOT, "testdata", "apps", "academy")
FALAKME = os.path.join(ROOT, "testdata", "apps", "falakme")
TENANTS = {"alice": "aaaaaaaa-0000-4000-8000-000000000001", "bob": "bbbbbbbb-0000-4000-8000-000000000002", "admin": "aaaaaaaa-0000-4000-8000-000000000001"}
STUDIO_BIN = sys.argv[4]
OFFICE_DB = sys.argv[5] if len(sys.argv) > 5 else ""
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
        with _http.urlopen(req, timeout=10) as r:
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


FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "crates", "falak-office", "tests", "fixtures")


def b64u(raw):
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def idp_token(claims):
    """An RS256 ID token, signed with the test key by `openssl` (no Python crypto needed)."""
    head = b64u(json.dumps({"alg": "RS256", "kid": "test-1", "typ": "JWT"}).encode())
    body = b64u(json.dumps(claims).encode())
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", os.path.join(FIXTURES, "oidc_test_key.pem")],
        input=f"{head}.{body}".encode(), capture_output=True, check=True,
    ).stdout
    return f"{head}.{body}.{b64u(sig)}"


def start_idp(issuer_port):
    """A stand-in for Clerk, Auth0 and the like: discovery and a key set."""
    import http.server
    issuer = f"http://127.0.0.1:{issuer_port}"
    jwks = open(os.path.join(FIXTURES, "oidc_test_jwks.json")).read()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.well-known/openid-configuration":
                out = json.dumps({"issuer": issuer, "jwks_uri": issuer + "/jwks"})
            elif self.path == "/jwks":
                out = jwks
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out.encode())

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", issuer_port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return issuer, srv


def main():
    idp_url, idp = start_idp(port())
    office_port = port()
    office_url = f"http://127.0.0.1:{office_port}"
    data = os.path.join(work, "office")
    office_env = {"DATABASE_URL": OFFICE_DB} if OFFICE_DB else {}
    office_env.update({"FALAK_OIDC_ISSUER": idp_url, "FALAK_OIDC_AUDIENCE": "falak-office",
                       "FALAK_OIDC_AUTO_CREATE": "corp.test"})
    office_argv = [OFFICE_BIN, "serve", "--port", str(office_port), "--data", data, "--issuer", office_url]

    # Accounts are made by an administrator.
    pw = {"OFFICE_PW": PASSWORD, **office_env}
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "admin@example.com",
         "--password-env", "OFFICE_PW", "--role", "office_admin"], pw)
    run([OFFICE_BIN, "user", "add", "--data", data, "--email", "alice@example.com",
         "--password-env", "OFFICE_PW"], pw)
    for who in ("bob", "carol", "erin"):
        run([OFFICE_BIN, "user", "add", "--data", data, "--email", f"{who}@example.com",
             "--password-env", "OFFICE_PW"], pw)

    office = start(office_argv, "office.log", office_env)
    wait_up(office_url, "office", office)

    s, v = call(office_url, "POST", "/v1/auth/login", {"email": "admin@example.com", "password": PASSWORD})
    check("the administrator signs in", s == 200, f"{s} {v}")
    admin = v["access_token"]
    s, v = call(office_url, "POST", "/v1/auth/signup", {"email": "x@example.com", "password": PASSWORD})
    check("Office has no self sign-up", s == 404, s)

    # Sign in through an outside identity provider (passkeys and MFA are its job).
    claims = {"iss": idp_url, "aud": "falak-office", "sub": "idp_user_1", "email": "dana@corp.test",
              "email_verified": True, "iat": int(time.time()), "exp": int(time.time()) + 300}
    s, v = call(office_url, "POST", "/v1/auth/oidc/exchange", {"id_token": idp_token(claims)})
    check("a person from the identity provider signs in to Office", s == 200 and "access_token" in v, f"{s} {v}")
    dana = v["access_token"] if s == 200 else ""
    s, v = call(office_url, "POST", "/v1/auth/oidc/exchange", {"id_token": idp_token({**claims, "aud": "other"})})
    check("a token for another audience is refused", s == 401, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/auth/oidc/exchange",
                {"id_token": idp_token({**claims, "sub": "x", "email": "eve@elsewhere.test"})})
    check("a stranger from another domain is refused", s == 401, f"{s} {v}")

    # Two apps, enrolled with one-time tokens.
    apps = {}
    for name, tier in (("notebook", 1), ("journal", 2), ("academy", 1), ("falakme", 1)):
        d = os.path.join(work, name)
        source = {"academy": ACADEMY, "falakme": FALAKME}.get(name, NOTEBOOK)
        shutil.copytree(source, d, ignore=shutil.ignore_patterns("web", ".falak", "node_modules"))
        if name == "journal":
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
    teachers = ("alice", "erin")
    for who in ("alice", "bob", "carol", "erin"):
        for name in apps:
            if name != "academy" and who in ("carol", "erin"):
                continue
            roles = ["teacher"] if name == "academy" and who in teachers else []
            member = {"email": f"{who}@example.com", "app": name, "roles": roles}
            if name == "falakme":
                member["tenant"] = TENANTS[who]
            s, v = call(office_url, "PUT", "/v1/_office/memberships", member, admin)
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

    s, v = call(office_url, "PUT", "/v1/_office/memberships",
                {"email": "dana@corp.test", "app": "notebook", "roles": []}, admin)
    check("an administrator gives the new person a membership", s == 200, f"{s} {v}")
    s, v = call(office_url, "POST", "/v1/_office/token", {"audience": "notebook"}, dana)
    check("the provider's person gets an app token", s == 200, f"{s} {v}")
    s, _ = call(urls["notebook"], "POST", "/v1/notebooks", {"title": "Dana's"}, v["access_token"])
    check("and uses the app with it", s == 201, s)

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

    # A third app, with relationship rules: teachers reach their own course's work.
    def tok(who, name="academy"):
        return app_token(session(f"{who}@example.com"), name)

    A, teacher, bob_t, carol_t, erin_t = urls["academy"], tok("alice"), tok("bob"), tok("carol"), tok("erin")
    s, course = call(A, "POST", "/v1/courses", {"title": "Maths", "description": "d", "published": True}, teacher)
    check("a teacher makes a course", s == 201, f"{s} {course}")
    s, _ = call(A, "POST", "/v1/courses", {"title": "Nope"}, bob_t)
    check("a student cannot make a course", s in (403, 404), s)
    s, _ = call(A, "POST", "/v1/enrollments", {"course_id": course["id"]}, bob_t)
    check("a student enrolls", s == 201, s)
    s, mine = call(A, "POST", "/v1/submissions", {"course_id": course["id"], "title": "Bob's essay", "body": "x"}, bob_t)
    check("a student submits work", s == 201, f"{s} {mine}")
    s, _ = call(A, "POST", "/v1/submissions", {"course_id": course["id"], "title": "Carol's essay", "body": "y"}, carol_t)
    titles = lambda path, t: sorted(r.get("title", r.get("name", "")) for r in (call(A, "GET", path, token=t)[1] or {}).get("data", []))
    check("the course's teacher reads every submission", titles("/v1/submissions", teacher) == ["Bob's essay", "Carol's essay"], titles("/v1/submissions", teacher))
    check("a student reads only their own", titles("/v1/submissions", bob_t) == ["Bob's essay"], titles("/v1/submissions", bob_t))
    check("another teacher reads none of them", titles("/v1/submissions", erin_t) == [], titles("/v1/submissions", erin_t))
    s, roster = call(A, "GET", "/v1/enrollments", token=teacher)
    check("the teacher sees the roster", s == 200 and len(roster["data"]) == 1, f"{s} {roster}")
    s, _ = call(A, "GET", f"/v1/submissions/{mine['id']}", token=erin_t)
    check("a teacher of another course gets 404 on the work", s == 404, s)
    s, review = call(A, "POST", "/v1/reviews", {"submission_id": mine["id"], "grade": 90, "feedback": "good"}, teacher)
    check("the teacher reviews it", s == 201, f"{s} {review}")
    s, mine_reviews = call(A, "GET", "/v1/reviews", token=bob_t)
    check("the student sees the review of their own work", s == 200 and len(mine_reviews["data"]) == 1, f"{s} {mine_reviews}")
    s, other = call(A, "GET", "/v1/reviews", token=carol_t)
    check("another student does not", s == 200 and other["data"] == [], f"{s} {other}")
    s, _ = call(A, "POST", "/v1/reviews", {"submission_id": mine["id"], "grade": 100}, bob_t)
    check("a student cannot grade themselves", s in (403, 404), s)
    s, _ = call(A, "PATCH", f"/v1/courses/{course['id']}", {"title": "mine now"}, bob_t)
    check("a student cannot change a course", s in (403, 404), s)

    # Studio: one admin interface, two apps, no app-specific code.
    studio_port = port()
    studio_url = f"http://127.0.0.1:{studio_port}"
    cfg_path = os.path.join(work, "studio.json")
    json.dump({"office_url": office_url, "apps": [{"name": n, "url": urls[n]} for n in ("notebook", "journal", "falakme")]},
              open(cfg_path, "w"))
    for name in ("notebook", "journal", "falakme"):
        member = {"email": "admin@example.com", "app": name, "roles": ["admin"]}
        if name == "falakme":
            member["tenant"] = TENANTS["admin"]
        s, v = call(office_url, "PUT", "/v1/_office/memberships", member, admin)
        check(f"the administrator is a member of {name}", s == 200, f"{s} {v}")
    start([STUDIO_BIN, "serve", "--config", cfg_path, "--port", str(studio_port), "--data", os.path.join(work, "studio")],
          "studio.log")
    wait_up(studio_url, "studio", procs[-1])
    st = _http.urlopen(studio_url + "/").headers
    check("Studio's page has a strict content security policy",
          "script-src 'self'" in (st.get("Content-Security-Policy") or "") and "unsafe-inline" not in (st.get("Content-Security-Policy") or ""))
    s, _ = call(studio_url, "GET", "/api/me")
    check("Studio answers 401 without a session", s == 401, s)
    s, v = call(studio_url, "POST", "/api/login", {"email": "alice@example.com", "password": PASSWORD})
    check("a person with no Studio role cannot sign in", s == 401, f"{s} {v}")

    class Studio:
        cookie = csrf = None

        def req(self, method, path, body=None):
            data = None if body is None else json.dumps(body).encode()
            r = urllib.request.Request(studio_url + path, data=data, method=method)
            if data is not None:
                r.add_header("Content-Type", "application/json")
            if self.cookie:
                r.add_header("Cookie", self.cookie)
            if self.csrf and method != "GET":
                r.add_header("X-Studio-CSRF", self.csrf)
            try:
                with _http.urlopen(r, timeout=15) as resp:
                    return resp.status, parse(resp.read()), resp.headers
            except urllib.error.HTTPError as e:
                return e.code, parse(e.read()), e.headers

    st = Studio()
    s, v, h = st.req("POST", "/api/login", {"email": "admin@example.com", "password": PASSWORD})
    check("the administrator signs in to Studio", s == 200, f"{s} {v}")
    st.cookie, st.csrf = h["Set-Cookie"].split(";")[0], v["csrf"]
    check("Studio's cookie is HttpOnly and SameSite=Strict", "HttpOnly" in h["Set-Cookie"] and "SameSite=Strict" in h["Set-Cookie"])
    check("Studio lists the apps from its config", v["apps"] == ["notebook", "journal", "falakme"], v)
    edited = {}
    for name in ("notebook", "journal"):
        s, sch, _ = st.req("GET", f"/api/apps/{name}/schema")
        paths = [e["path"] for e in (sch or {}).get("entities", [])]
        check(f"Studio reads {name}'s schema and `admin:` metadata", s == 200 and "notebooks" in paths, f"{s} {sch}")
        label = next(e for e in sch["entities"] if e["path"] == "notebooks")["admin"]["label"]
        check(f"the label for {name} comes from the app, not from Studio", bool(label), label)
        s, rec, _ = st.req("POST", f"/api/apps/{name}/notebooks", {"values": {"title": f"made in Studio ({name})"}})
        check(f"Studio creates a record in {name}", s == 201, f"{s} {rec}")
        s, rec2, _ = st.req("PATCH", f"/api/apps/{name}/notebooks/{rec['id']}",
                            {"changes": {"title": f"edited in Studio ({name})"}, "version": rec["version"]})
        check(f"Studio edits it in {name}", s == 200 and rec2["title"].startswith("edited"), f"{s} {rec2}")
        s, stale, _ = st.req("PATCH", f"/api/apps/{name}/notebooks/{rec['id']}",
                             {"changes": {"title": "again"}, "version": rec["version"]})
        check(f"an edit from a stale version is refused in {name}", s in (409, 412), f"{s} {stale}")
        edited[name] = rec["id"]
    # Personal data: Falak.me's `bio` is marked `pii`. Studio masks it and reveals on request.
    s, p_rec, _ = st.req("POST", "/api/apps/falakme/profiles", {"values": {"display_name": "Dana", "bio": "Lives at 12 Secret Street"}})
    check("Studio creates a Falak.me profile", s == 201, f"{s} {p_rec}")
    s, page, _ = st.req("GET", "/api/apps/falakme/profiles")
    row = next((r for r in (page or {}).get("data", []) if r.get("id") == p_rec.get("id")), {})
    check("Studio masks personal data in lists", "Secret Street" not in json.dumps(page) and "•" in str(row.get("bio")), page)
    s, shown, _ = st.req("POST", f"/api/apps/falakme/profiles/{p_rec['id']}/reveal", {})
    check("revealing is a separate step that returns the real value", s == 200 and shown["data"]["bio"] == "Lives at 12 Secret Street", f"{s} {shown}")
    s, _, _ = st.req("PATCH", f"/api/apps/falakme/profiles/{p_rec['id']}", {"changes": {"bio": "A•••••"}, "version": p_rec["version"]})
    check("a masked value cannot be saved over the real one", s == 400, s)
    bob_t = tok("bob", "falakme")
    s, others = call(urls["falakme"], "GET", "/v1/profiles", token=bob_t)
    check("another workspace sees none of it", s == 200 and others["data"] == [], f"{s} {others}")

    # The change is really in the app, read there with the same person's token.
    for name in ("notebook", "journal"):
        tok = app_token(session("admin@example.com"), name)
        s, got = call(urls[name], "GET", f"/v1/notebooks/{edited[name]}", token=tok)
        check(f"the edit is in {name} itself", s == 200 and got["title"].startswith("edited"), f"{s} {got}")
    # The apps' policies still decide: Studio cannot reach someone else's record.
    s, other = call(urls["notebook"], "POST", "/v1/notebooks", {"title": "Alice's private"}, t_nb)
    s2, _, _ = st.req("PATCH", f"/api/apps/notebook/notebooks/{other['id']}", {"changes": {"title": "x"}, "version": other["version"]})
    s3, after = call(urls["notebook"], "GET", f"/v1/notebooks/{other['id']}", token=t_nb)
    check("Studio cannot change a record the app does not give this person",
          s2 in (403, 404, 412) and s3 == 200 and after["title"] == "Alice's private", f"{s2} {after}")
    log = os.path.join(work, "studio", "audit.jsonl")
    out = subprocess.run([STUDIO_BIN, "audit-verify", log], capture_output=True, text=True)
    check("Studio's audit log verifies and has the writes", out.returncode == 0 and "entries" in out.stdout, out.stdout + out.stderr)
    check("the audit log holds who and what, never the values", "edited in Studio" not in open(log).read())
    s, _, _ = st.req("POST", "/api/logout", {})
    check("the administrator signs out of Studio", s == 200, s)

    # The page itself, in a real Chrome (needs `npm ci` in scripts/ui; set FALAK_UI_DIR).
    ui = os.environ.get("FALAK_UI_DIR")
    if ui:
        script = os.path.join(os.path.dirname(__file__), "..", "ui", "studio-ui.mjs")
        r = subprocess.run(["node", script, studio_url, "admin@example.com", PASSWORD, ui], capture_output=True, text=True)
        print(r.stdout.rstrip())
        check("Studio's page works in Chrome: forms, masking, no injected markup, fits a phone", r.returncode == 0, r.stdout[-800:] + r.stderr[-400:])

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
    idp.shutdown()
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
