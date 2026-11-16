# Federation Specification

* **Status:** **1.0, frozen** (2026-11-16). Sections 1 to 12 ran together in `scripts/smoke/office.sh` (SQLite and PostgreSQL) and `scripts/smoke/office-workers.py` (Workers, D1). Section 13, events and sagas, ran in `scripts/smoke/events.sh` (native, Office on SQLite and PostgreSQL). From here a change to a wire format, a table or a rule in this document is a new major version of the specification. Tier 3 is still not implemented.
* **Owner:** Dev3 for this draft. Office: Dev2 (registry), Dev4 (identity).
* **Scope:** how an app joins Falak Office, how a person signs in once and reaches several apps, how an app learns that a token or an app was revoked, and what an app does when Office cannot be reached. Section 13 specifies events and sagas.

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
4. The app verifies it locally with the cached key set. It trusts only keys from the configured issuer's JWKS, fetched over `https` (or a loopback address in development). The set is fetched again after 60 seconds. A token with an unknown `kid` fetches it at once, before the token is checked, but at most once every 2 seconds, so made-up key ids cannot become a stream of requests to Office.

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

The cached key set is used for as long as tokens signed by it can still be valid. An app that has never reached Office has no keys and refuses every token.

**Runtimes with no memory between requests (Workers).** Isolates start and stop at will and have no timers. Such a runtime keeps up with Office on requests, at most once every 20 seconds per instance, before it routes the request, and saves the last good key set and feed state (version, time of the last feed, what it revoked) in the app's own database, in the table `falak_office_cache`. A new instance starts from that save, so tier 1 keeps working, revocations stay honored and the tier 2 staleness limit keeps counting from the last feed even when Office is down and the instance is new.

## 9. Signing in through an identity provider

Office accepts ID tokens from one configured OpenID Connect provider (ADR-0011). `POST /v1/auth/oidc/exchange` with `{"id_token": "..."}` returns the same body as `/v1/auth/login` (`access_token`, `refresh_token`, `expires_in`). The token must verify against the provider's key set (algorithm from the asymmetric list only), name the configured issuer, carry the configured audience in `aud` or `azp`, be unexpired, and carry a verified `email`. Office links `(iss, sub)` to an account on first use. A subject revoked in the feed cannot sign in again. Without a configured provider the route answers `404`. Every refusal is `401` with the same body.

## 10. Step-up

For a sensitive action, `POST /v1/_office/stepup` with an Office session, `{"audience": "<app>", "id_token": "<fresh provider ID token>"}`. The ID token MUST carry `auth_time` within the last 5 minutes and MUST be for the provider identity linked to the session's person. The reply is an app token like `/v1/_office/token`, with the role `step_up` added and a life of at most 5 minutes. Office never grants `step_up` through a membership. Policies that guard the action require that role. Without a configured provider the route answers `404`.

## 11. Studio

Studio is an app of Office, not part of it. It signs people in through Office (`/v1/auth/login` or the exchange in §9) and only for people holding the Office role `office_admin` or `studio`. It keeps the Office session on the server behind an `HttpOnly`, `SameSite=Strict` cookie, takes an app token per app with `/v1/_office/token`, and reads and writes only through each app's API, so each app's policies decide. Apps describe themselves to it with `GET /v1/_schema` (the entities the caller may read, what they may do, field types and the `admin:` metadata). Personal fields (`pii`, `encrypted`) are masked by Studio; showing one is a separate call that is written to Studio's hash-chained audit log, as is every sign-in and write. The log holds who, what and which record, never values.

## 12. Not in this version

Passkeys (the identity provider's job, ADR-0011) and sender-constrained tokens (tier 3).

---

## 13. Events and sagas

Events carry facts from one app to others, durably. Delivery is at least once and ordered per aggregate; each consumer applies an event once. An app declares what it publishes and consumes in `events/*.yaml`, and Office delivers only what those contracts allow. The file formats are SCHEMA §14.

### 13.1 Contracts

An app tells Office its contract with `PUT /v1/_office/events/contract` (app signed, §4):

```json
{ "events": [ {"name": "order_placed", "version": 1, "subscribers": ["inventory"]} ],
  "subscriptions": [ {"event": "order_placed", "from": "orders", "version": 1} ],
  "sagas": [ {"name": "fulfil_order", "start": "order_placed",
              "steps": [ {"name": "confirm", "command": "inventory.confirm_stock", "compensate": "inventory.cancel_stock"} ]} ] }
```

The app sends its contract each time it starts. Office keeps the latest per app. Office MUST NOT accept an event the publisher's contract does not declare, with the declared version, and MUST NOT deliver an event to an app the publisher's contract does not name in `subscribers`. A consumer MUST ignore an event it has no subscription for, and MUST refuse one whose version is not the version it consumes (the event is dead-lettered).

### 13.2 Outbox and inbox

An app that publishes or consumes events has two tables, made with the rest of its schema:

* `_falak_outbox(seq, id, event, entity, aggregate_id, revision, schema_version, payload, occurred_at, sent_at)`. A change that raises an event writes the outbox row **in the same atomic batch** as the change: both happen or neither does. After an update or delete the row is added only if the write changed a row. The event id is `<request id>:<event name>`; `revision` is the aggregate's `version` after the change; the payload is the declared fields the change carried (on create, a declared default fills a missing one) and `id`.
* `_falak_inbox(event_id, publisher, name, received_at)`. A consumer applies an event by running the handler's write and inserting the inbox row **in one atomic batch**. A repeat violates the primary key, rolls the batch back and is recognised as already applied.

The **relay** sends unsent outbox rows to Office in `seq` order and marks a row sent only after Office answered `200`. It stops at the first failure, so order is kept, and starts again from there. Sent rows are deleted after 7 days; inbox rows after 30 days (longer than Office keeps an event, so a redelivery is always recognised).

An event handler runs with the principal `event:<publisher>` and the role `event_consumer`. The handler's entity policy MUST allow that role to create the row (default deny applies). The handler is a `create` command; the payload's fields feed the command's inputs by name.

### 13.3 Compatibility

Between two builds of an app, removing an event, removing or retyping a payload field, or changing the entity or trigger that raises an event is a breaking change. It MUST come with a higher `version`; the compiler refuses it otherwise. Adding an event or a field is compatible. A version never goes down.

### 13.4 Wire format and signing

**Publish.** `POST /v1/_office/events` (app signed):

```json
{ "id": "...", "event": "order_placed", "aggregate_type": "purchase", "aggregate_id": "...",
  "revision": 1, "version": 1, "occurred_at": 1760000000000000, "payload": "<JSON text>", "signature": "<base64url>" }
```

`signature` is Ed25519, by the publisher's app key, over

```text
"falak-event\n" publisher "\n" id "\n" event "\n" aggregate_type "\n" aggregate_id "\n" revision "\n" version "\n" occurred_at "\n" hex(sha256(payload))
```

Office verifies it against the publisher's registered key, checks the contract, then **stores the event and one delivery for each named subscriber in one transaction, and only then answers `200 {seq}`**. A publish of an id Office already has answers `200` with the same `seq` and changes nothing. Anything else means the event is not stored.

**Claim.** `POST /v1/_office/events/claim {limit}` (app signed) returns the caller's deliveries that are waiting and due, oldest first, at most 100. A delivery comes back until it is acknowledged. A delivery is withheld while an earlier delivery for the same subscriber, publisher and aggregate (`aggregate_type`, `aggregate_id`) is waiting or dead, so events of one aggregate arrive one at a time, in order. Each item carries the event as published plus `signer`, `kid`, and for an app-signed event `publisher_key` and `key_attestation`.

**Verify.** A subscriber MUST check an event before applying it. For an app-signed event: `key_attestation` is an Office signature, by key `kid` from the issuer's key set (§1), over `"falak-app-key\n" app "\n" publisher_key`; then `signature` MUST verify with `publisher_key` over the text above. For an event Office signed itself (`signer` is `office`, a saga command), `signature` MUST verify with Office key `kid` over `"office\n"` followed by the same text. An event that fails is acknowledged `fail`; it is never applied.

**Acknowledge.** `POST /v1/_office/events/ack {seq, outcome, error?}` (app signed) after the handler's transaction has committed. `ok`: done. `retry`: the delivery waits `2^attempts` seconds and is tried again; after 5 attempts it is dead. `fail`: dead at once. A caller can acknowledge only its own deliveries. An acknowledgement lost on the way only causes a redelivery, which the inbox recognises.

**Dead letters.** `GET /v1/_office/events/dead` lists dead deliveries (administrator). `POST /v1/_office/events/replay {seq, subscriber}` puts one back in the queue; it is recorded in the audit log. A dead delivery keeps blocking later events of its aggregate until it is replayed.

**Retention.** Office deletes an event, and its deliveries, 7 days after it was stored if every delivery is done. Dead and waiting deliveries are kept.

### 13.5 Sagas

A saga is started when Office stores an event that its owner's contract names in `start`. Office keeps one instance per start, with the steps as they were then, and runs them in order:

1. For step *i* it stores a command event, `aggregate_type` `saga`, `aggregate_id` the saga id, named by the step's `command` (`<app>.<event>`), published as the saga's owner and signed by Office, with the starting event's payload and `saga_id`. The target app MUST consume that event from the owner (13.1); otherwise the step fails.
2. When the delivery is acknowledged `ok`, step *i + 1* is sent; after the last step the saga is `completed`.
3. When a step's delivery goes dead (or cannot be sent), the saga is `compensating`: for each earlier step that has a `compensate`, newest first, Office sends that event the same way and waits for `ok`. The failed step itself is not compensated. When none is left the saga is `compensated`. A compensation that goes dead leaves the saga `stuck`, for a person.

`GET /v1/_office/sagas` (administrator) lists instances and counts by state.

### 13.6 Runtimes

The native runtime runs the relay and the consumer as loops (`falak serve`, when the app is enrolled). A Worker has no background thread: a Cron Trigger (every minute, written by `falak deploy`) and every successful write run one pass of the same logic with `ctx.wait_until`. Both keep all state in the app's database, so a restart or another isolate continues where the last stopped.

### 13.7 Limits of this version

* Events need the app to be enrolled with Office. Without it the outbox fills and nothing is sent.
* `tenancy: database` apps cannot use events. An app with `tenancy: row` can publish but not consume (an event carries no tenant).
* An event handler is a `create` command. Update-style effects are modelled as new rows.
* Office keeps one contract per app and does not check a consumer's version against the publisher's across apps; a mismatch is a dead letter, visible in the dead-letter list.
