# Federation Specification

* **Status:** Draft 1 (2026-11-15). Candidate when the Registry, Identity and the federation client have run together (T4.13).
* **Owner:** Dev3 for this draft. Office: Dev2 (registry), Dev4 (identity).
* **Scope:** how an app joins Falak Office, how a person signs in once and reaches several apps, how an app learns that a token or an app was revoked, and what an app does when Office cannot be reached. Events and sagas are specified at M5.

Words in capitals (MUST, MUST NOT, SHOULD) are used in their usual specification sense. Trust tiers are defined in ARCHITECTURE §4.6.

---

## 1. Parties and keys

* **Office** signs tokens, passports and revocation feeds with Ed25519 keys it holds. Several keys can be valid at once (§7). Office publishes the public keys at `GET /.well-known/jwks.json` (a JWK set, `kty` `OKP`, `crv` `Ed25519`, `kid`). The set is public and MAY be cached for five minutes.
* **An app** holds one Ed25519 key pair, made when it enrolls. The private key never leaves the app. Office holds the public key.
* **A person** has an account in Office. Office never gives an app a password or a reusable credential: an app only sees short-lived access tokens for its own audience.
* The algorithm is always EdDSA. A token or document that names another algorithm is refused. `kid` is required.

## 2. Enrollment

1. An Office administrator makes an **enrollment token** for an app name and tier: `POST /v1/_office/enrollments {app, tier, capabilities}`. The token is 32 random bytes, shown once, valid for 15 minutes and for one use. Office stores only its SHA-256.
2. The app generates its key pair and calls `POST /v1/_office/enroll`:

   ```json
   { "token": "...", "app": "notebook", "public_key": "<base64url, 32 bytes>",
     "timestamp": 1760000000, "nonce": "<random>", "signature": "<base64url>" }
   ```

   `signature` is Ed25519, by the app's new key, over `"falak-enroll\n" + app + "\n" + public_key + "\n" + nonce + "\n" + timestamp`. It proves the caller holds the private key.
3. Office checks the timestamp (within 60 seconds), the token (unused, unexpired, for this app), the proof, and that the app name is free. Marking the token used and creating the app happen in one transaction: a token enrolls at most one app, once.
4. Office answers `201 {app, tier, passport, issuer, jwks_url}`.

An app name is `^[a-z][a-z0-9_-]{1,39}$` and is also the token audience (one audience per app).

## 3. App Passport

A passport is a signed statement by Office about an app: `base64url(header).base64url(payload).base64url(signature)`, EdDSA.

```json
{ "iss": "<office issuer>", "sub": "<app>", "kind": "passport", "tier": 1,
  "capabilities": ["..."], "app_key": "<base64url public key>",
  "iat": 0, "exp": 0, "jti": "<id>" }
```

A passport lasts at most 90 days. It is revoked by adding its `jti` or the app to the revocation feed. A revoked app can no longer call Office and its audience is refused tokens.

## 4. Requests from an app to Office

Every request an app makes to `/v1/_office/*` (other than `enroll`) is signed:

```text
X-Falak-App: <app>
X-Falak-Timestamp: <unix seconds>
X-Falak-Nonce: <random, at least 16 characters>
X-Falak-Signature: base64url(Ed25519(app key, METHOD "\n" PATH-AND-QUERY "\n" timestamp "\n" nonce "\n" hex(sha256(body))))
```

Office MUST refuse a request whose timestamp is more than 60 seconds off, whose nonce it has seen from that app within the last two minutes, whose signature does not verify with the app's public key, or whose app is revoked. Refusals are `401` with a generic problem document.

`GET /v1/_office/manifest` answers an enrolled app with `{issuer, audience, tier, jwks_url, revocations_url, feed_version, now}`.

## 5. Signing in once

1. A person signs in to Office: `POST /v1/auth/login {email, password}` (the same routes as local identity, with audience `office`). Refresh tokens rotate on every use; presenting a used refresh token ends the whole family.
2. For each app, the client asks Office for a token: `POST /v1/_office/token {audience}` with the Office access token. Office issues it only if the app is enrolled and not revoked, and the person has a membership for it.
3. The access token is an EdDSA JWT with `iss`, `aud` (the app), `sub`, `exp`, `iat`, `jti`, `kid`, and `tenant` and `roles` for that app from the membership. Lifetime: 15 minutes for tier 1, 5 minutes for tiers 2 and 3.
4. The app verifies it locally with the cached key set. It trusts only keys from the configured issuer's JWKS, fetched over `https` (or a loopback address in development). An unknown `kid` may cause one refetch, at most every 30 seconds.

A person with no membership for an app gets `403` from Office and cannot obtain a token for it. Memberships are made by an administrator (`PUT /v1/_office/memberships`). Office is the source of the tenant: a tenant or role in a request is never trusted.

## 6. Revocation feed

`GET /v1/_office/revocations?since=<version>` (app signed) returns a signed document:

```json
{ "payload": "<JSON text>", "kid": "<key id>", "signature": "<base64url>" }
```

where the payload is `{ "version": 12, "issued_at": 0, "ttl_secs": 60, "entries": [ {"kind": "token"|"subject"|"app"|"passport", "id": "...", "at": 0 } ] }`. `version` rises by one with every revocation and never falls. A client MUST verify the signature with a key from the key set, MUST ignore a document whose version is lower than one it has seen, and applies the entries: a revoked `jti` or `sub` is refused until the token would have expired anyway.

Administrators revoke with `POST /v1/_office/revocations {kind, id}`.

## 7. Key rotation

`POST /v1/_office/keys/rotate` (administrator) adds a new key and makes it the signing key. The old keys stay in the key set, so tokens already issued keep verifying. `POST /v1/_office/keys/retire` removes every key except the active one; an administrator calls it after the longest token lifetime has passed. A client never needs to be told: it meets the new `kid` and refetches the set (§5.4). No request fails because of a rotation.

## 8. When Office is unreachable

| Tier | Verification | Revocation | Behaviour while the feed is stale |
| :-- | :-- | :-- | :-- |
| 1 | Local, cached keys | By expiry only | Keeps working. Tokens that expire cannot be renewed, which is the client's concern. |
| 2 | Local, cached keys | The feed, with a staleness limit (default 5 minutes) | After the limit the app is **read only**: `GET` and `HEAD` work, anything else answers `503` `office_unavailable`. |
| 3 | Local, plus an online check per sensitive command | Online | Sensitive commands stop. Not implemented in this draft: an app declared tier 3 refuses to start under Office. |

The cached key set is used for as long as tokens signed by it can still be valid. An app that has never reached Office since it started has no keys and refuses every token.

## 9. Not in this draft

OIDC provider wrapping and passkeys (ADR-0004: the provider is an owner decision), sender-constrained tokens (tier 3), step-up authentication, events, sagas and the Studio protocol.
