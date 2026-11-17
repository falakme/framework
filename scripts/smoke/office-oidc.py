#!/usr/bin/env python3
"""The checks for office-oidc.sh: a person signs in at Dex and uses the ID token at Office."""

import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import _http

ISSUER, OFFICE = _http.base_url(sys.argv[1]), _http.base_url(sys.argv[2])
failed = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{detail}]"))
    if not ok:
        failed.append(name)


def call(method, url, body=None, headers=None, form=None):
    data = None
    h = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with _http.urlopen(req, timeout=15) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")


def claims(token):
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def dex_token(email, password):
    basic = base64.b64encode(b"falak-office:not-a-secret").decode()
    s, v = call("POST", ISSUER + "/token", headers={"Authorization": "Basic " + basic},
                form={"grant_type": "password", "username": email, "password": password, "scope": "openid email profile"})
    return s, v


s, v = dex_token("dana@example.com", "password")
check("Dex signs a person in", s == 200 and "id_token" in v, f"{s} {v}")
id_token = v["id_token"]
c = claims(id_token)
check("Dex's ID token is for Office, from Dex, with a verified email",
      c["iss"] == ISSUER and c["aud"] == "falak-office" and c["email"] == "dana@example.com" and c.get("email_verified") is True, c)

s, me = call("POST", OFFICE + "/v1/auth/oidc/exchange", {"id_token": id_token})
check("Office accepts it and gives a session (key set found by discovery)", s == 200 and "access_token" in me, f"{s} {me}")
session = claims(me["access_token"])
check("the session is for a new account made for the allowed domain", bool(session.get("sub")), session)

s, again = call("POST", OFFICE + "/v1/auth/oidc/exchange", {"id_token": id_token})
check("the same person signing in again is the same account",
      s == 200 and claims(again["access_token"])["sub"] == session["sub"], f"{s}")

head, body, sig = id_token.split(".")
flipped = sig[:-3] + ("AAA" if not sig.endswith("AAA") else "BBB")
s, _ = call("POST", OFFICE + "/v1/auth/oidc/exchange", {"id_token": f"{head}.{body}.{flipped}"})
check("a token with a damaged signature is refused", s == 401, s)

forged = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
forged["email"] = "admin@example.com"
body2 = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
s, _ = call("POST", OFFICE + "/v1/auth/oidc/exchange", {"id_token": f"{head}.{body2}.{sig}"})
check("a token whose claims were edited is refused", s == 401, s)

s, v = dex_token("dana@example.com", "wrong")
check("Dex itself refuses a wrong password", s in (400, 401), f"{s} {v}")

if failed:
    sys.exit(f"{len(failed)} check(s) failed")
print("office oidc smoke: all checks passed")
