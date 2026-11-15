# Falak API Specification

**Status:** Frozen 1.0 (2026-11-15, ADR-0009). Changes only by ADR.  
**Author:** Dev2 (Native Runtime & Data Lead).  
**Frozen at:** Milestone M2 exit.  
**Audience:** Dev5 (SDK codegen, Studio, and Notebook app), Dev3 (Edge runtime & CLI), Dev4 (Security middleware).

---

## 1. Protocol Architecture & Conventions

Falak applications expose a uniform HTTP API compiled directly from domain entity manifests, command definitions, and authorization policies.

### 1.1 HTTP Semantics
* **Protocols:** HTTP/1.1 and HTTP/2 over TLS 1.3 (or TLS 1.2 minimum).
* **Base Path:** All framework-generated endpoints are rooted at `/v1`.
* **Content Types:**
  * Request payload: `Content-Type: application/json; charset=utf-8`
  * Successful response: `Content-Type: application/json; charset=utf-8`
  * Error response: `Content-Type: application/problem+json; charset=utf-8` (RFC 7807)
* **Character Encoding:** UTF-8 required for all inputs. Strings are normalized to Unicode Normalization Form C (NFC) prior to comparison, indexing, or persistence.
* **Date & Time:** ISO 8601 / RFC 3339 strings in UTC with millisecond precision (e.g., `2026-11-15T14:30:00.000Z`).
* **Identifiers:** Canonical UUIDv7 or UUIDv4 formatted as lowercase 36-character hyphenated strings (`018f6c4a-67a2-7b81-9b1e-355f309a4d88`).
* **Monetary Values:** `decimal_minor` is represented as integer numbers of minor currency units (e.g., `1050` represents `$10.50` USD), never floating-point numbers.

### 1.2 Caching & Privacy Headers
* **Default Caching:** Responses containing tenant or user-scoped data automatically include:
  `Cache-Control: private, no-cache, no-store, must-revalidate`
  `Pragma: no-cache`
* **Public Entities:** Endpoints explicitly marked `public` in entity metadata may emit public caching directives (`Cache-Control: public, max-age=300`). Edge caches are strictly prohibited from sharing cached responses across distinct bearer tokens.

---

## 2. Keyset Pagination (Cursor-Based)

To maintain $O(1)$ query execution, prevent page-drift anomalies during concurrent writes, and eliminate costly SQL `OFFSET` scans, Falak mandates deterministic keyset pagination.

### 2.1 Query Parameters
* `page[size]`: Integer, default `20`, maximum allowable `100`. Values exceeding `100` are clamped or rejected with `400 Bad Request`.
* `page[after]`: Opaque base64url-encoded cursor representing the position after which records should be fetched.
* `page[before]`: Opaque base64url-encoded cursor for reverse pagination.

### 2.2 Cursor Structure
Under the hood, cursors encode the sort values and the primary key of the boundary record:
`cursor = base64url(json({ "values": [created_at_micros, id] }))`
Cursors are signed or tamper-resistant to prevent client manipulation.

### 2.3 Response Envelope
All collection endpoints return a standardized data and metadata envelope:
```json
{
  "data": [
    {
      "id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
      "title": "Architecture Notes",
      "version": 1
    }
  ],
  "meta": {
    "page_size": 20,
    "has_more": true,
    "next_cursor": "eyJ2YWx1ZXMiOlsxNzYzMjE3MDAwMDAwMDAwLCIwMThmNmM0YS02N2EyLTdiODEtOWIxZS0zNTVmMzA5YTRkODgiXX0",
    "prev_cursor": null
  }
}
```
When `has_more` is `false`, `next_cursor` is `null`.

---

## 3. Filtering, Sorting, and Field Selection

### 3.1 Filtering Syntax
Filters are provided as query parameters nested under the `filter` namespace.

* **Exact Equality:** `filter[<field>]=<value>`  
  *Example:* `GET /v1/notes?filter[archived]=false`
* **Explicit Operators:** `filter[<field>][<operator>]=<value>`
  * `eq`: Equal to (`filter[status][eq]=active`)
  * `neq`: Not equal to (`filter[status][neq]=archived`)
  * `gt`: Greater than (`filter[priority][gt]=2`)
  * `gte`: Greater than or equal to (`filter[created_at][gte]=2026-11-01T00:00:00Z`)
  * `lt`: Less than (`filter[priority][lt]=5`)
  * `lte`: Less than or equal to (`filter[created_at][lte]=2026-11-15T00:00:00Z`)
  * `in`: In array of comma-separated values (`filter[tag][in]=rust,sqlite,web`)
  * `like`: Text pattern matching (`filter[title][like]=%project%`)
  * `is_null`: Check for null/empty (`filter[deleted_at][is_null]=true`)

### 3.2 Complexity & Defense Limits
To prevent query-denial-of-service (QDoS) attacks, the query compiler enforces strict limits:
1. Maximum of `10` active filter predicates per request.
2. Maximum of `20` elements inside an `in` operator list.
3. Maximum pattern length of `100` characters for `like` queries (limited to `50` bytes on Cloudflare D1).
4. Leading wildcards (e.g. `%term`) on unindexed text fields may be rejected by the compiler if the driver lacks full-text index support.

### 3.3 Side-Channel Rules
* **Authorization Masking:** A caller cannot filter, sort, or aggregate on a column their policy denies reading.
* If a query attempts to filter on an unreadable field, the request is rejected with `400 Bad Request` (`invalid_filter`).
* If a record exists but the caller does not have read permissions for that record, it is completely excluded from list results, and direct `GET /v1/<entity>/:id` queries return `404 Not Found` (never `403 Forbidden`) to prevent existence probing.

### 3.4 Sorting Syntax
* Sorting is specified via the `sort` query parameter as a comma-separated list of field names.
* Ascending order is default. Prefix with `-` for descending order.
* *Example:* `GET /v1/notes?sort=-pinned,-created_at,id`
* Every sort list is deterministically completed by appending the primary key (`id`) if not already present.

### 3.5 Field Selection (Sparse Fieldsets)
* Syntax: `fields[<entity>]=field1,field2,...`
* *Example:* `GET /v1/notes?fields[note]=id,title,updated_at`

### 3.6 Relationships & Sideloading
* Syntax: `include=relation1,relation2`
* *Example:* `GET /v1/notes?include=notebook`
* Traversal depth is bounded (maximum depth `1` in v1, expandable to `2` in Phase 4). Deep circular includes are rejected at compile time.

---

## 4. Concurrency Control: ETags & If-Match

Falak enforces optimistic concurrency control using HTTP Entity Tags (`ETag`) derived from entity record versions.

1. **Version Field:** Every entity manifest includes a system-managed `version: int64` property (initialized to `1` on create, incremented atomically on update).
2. **Read Responses:** All single-record representations return an `ETag` header:
   `ETag: W/"1"`
3. **Mutation Preconditions:**
   Clients performing mutations (`PUT`, `PATCH`, or state-altering commands) can supply:
   `If-Match: W/"1"`
4. **Precondition Verification:**
   * If the current stored record version matches the `If-Match` header, the mutation succeeds, and the updated record is returned with `ETag: W/"2"`.
   * If the record has been updated concurrently (stored version $\neq$ header version), the runtime rejects the mutation without side effects, returning `412 Precondition Failed`:
     ```json
     {
       "type": "https://falak.me/errors/precondition-failed",
       "title": "Precondition Failed",
       "status": 412,
       "detail": "Resource was modified by another operation. Current version is 2.",
       "code": "precondition_failed",
       "instance": "/v1/notes/018f6c4a-67a2-7b81-9b1e-355f309a4d88"
     }
     ```

---

## 5. Idempotency Keys

To guarantee safe retries across flaky networks without risk of duplicate execution, mutations and custom domain commands accept an idempotency key.

### 5.1 Client Usage
* Clients generate a unique string (typically a UUIDv4) and transmit it via the `Idempotency-Key` header:
  `Idempotency-Key: 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`

### 5.2 Server Semantics
1. **Scope:** Idempotency keys are strictly scoped to the combination of `(principal_subject, http_method, request_path, idempotency_key)`. Callers cannot probe or replay another user's idempotency key.
2. **Payload Fingerprint:** The server computes a SHA-256 hash of the request body. If the same key is reused with a different request payload, the server rejects the request with `422 Unprocessable Entity` (`idempotency_payload_mismatch`).
3. **In-Flight Requests:** If a second request arrives while the first is still processing, the server returns `409 Conflict` (`concurrent_mutation_in_progress`) with a `Retry-After: 1` header.
4. **Completed Requests:** When a request succeeds, the server caches the HTTP status code, selected response headers (`ETag`, `Content-Type`), and response body for 24 hours. Replaying the request returns the identical cached response accompanied by:
   `Idempotent-Replayed: true`
5. **Where keys live:** Every instance of an app that can receive the same retry MUST see the same keys. `falak serve` is one process and keeps them in memory. The Workers runtime has many isolates with no shared memory, so it keeps them in the app's database (`_falak_idempotency`). A key that stays in flight for more than 120 seconds is treated as left by a request that died, and the next request with that key proceeds.

---

## 6. Error Taxonomy & RFC 7807 Format

All error responses emit `Content-Type: application/problem+json; charset=utf-8` conforming to RFC 7807 and RFC 9457.

### 6.1 Schema Definition
```json
{
  "type": "https://falak.me/errors/<slug>",
  "title": "<Standard Status Title>",
  "status": 400,
  "detail": "<Safe Human-Readable Description>",
  "code": "<stable_snake_case_code>",
  "instance": "<request_path>",
  "request_id": "<correlation_id>",
  "invalid_params": [
    {
      "name": "<field_name>",
      "reason": "<field_error_description>",
      "code": "<field_error_code>"
    }
  ]
}
```

### 6.2 Error Mapping Table

| ErrorKind (`falak-contracts`) | HTTP Status | Standard Title | Example Code | Safe Public Detail Example |
| :--- | :--- | :--- | :--- | :--- |
| `InvalidInput` | `400` | Bad Request | `validation_failed` | "Request validation failed." |
| `Unauthenticated` | `401` | Unauthorized | `unauthenticated` | "Authentication is required." |
| `Forbidden` | `403` | Forbidden | `policy_denied` | "Not permitted." |
| `NotFound` | `404` | Not Found | `not_found` | "Not found." |
| `Conflict` | `409` | Conflict | `unique_violation` | "A record with this identifier already exists." |
| `PreconditionFailed` | `412` | Precondition Failed | `precondition_failed` | "Resource version mismatch." |
| `PayloadTooLarge` | `413` | Payload Too Large | `payload_too_large` | "The request body is too large." |
| `Unprocessable` | `422` | Unprocessable Entity | `idempotency_payload_mismatch` | "The idempotency key was previously used with a different request payload." |
| `RateLimited` | `429` | Too Many Requests | `rate_limited` | "Too many requests. Please retry later." |
| `Unsupported` | `501` | Not Implemented | `unsupported_capability` | "Operation not supported on this runtime." |
| `Unavailable` | `503` | Service Unavailable | `service_unavailable` | "Database is temporarily busy. Retry shortly." |
| `Timeout` | `504` | Gateway Timeout | `execution_timeout` | "The operation timed out." |
| `Internal` | `500` | Internal Server Error | `internal_error` | "An unexpected error occurred." |

### 6.3 Security Information Redaction Rule
Internal SQL text, table names, raw database driver errors, system paths, and stack traces **MUST NEVER** appear in the `detail` or `invalid_params` fields. The raw root cause is recorded solely in internal structured telemetry logs linked by `request_id`.

---

## 7. Rate Limiting Headers

Every response includes standard IETF rate limit headers:
* `RateLimit-Limit`: Maximum requests permitted in the window (e.g., `100`).
* `RateLimit-Remaining`: Remaining request count in the active window.
* `RateLimit-Reset`: Number of seconds until the current quota window resets.
* If throttled (`429 Too Many Requests`), the response additionally emits `Retry-After: <seconds>`.

A runtime whose limiter only answers yes or no (the Workers runtime, which counts with Cloudflare's rate limit binding) MUST NOT invent counts: it sends `Retry-After` on a `429` and no `RateLimit-*` headers.

### 7.1 Limits

The numbers below are defaults. They are properties of the runtime, not of the app.

| Limit | Default | Over the limit |
| :--- | :--- | :--- |
| Data routes, per client address | 600 requests per minute | `429` `rate_limited` |
| `/v1/auth/*`, per client address | 30 requests per minute | `429` `rate_limited` |
| Request body, data routes | 1 MiB | `413` `payload_too_large` |
| Request body, `/v1/auth/*` | 8 KiB | `400` `invalid_body` |
| Request time (`falak serve`) | 30 seconds | `504` `execution_timeout` |

`/healthz` and `/readyz` are never rate limited. The Workers runtime sets no timer of its own: Cloudflare enforces the CPU and wall time limits of the plan, and a request that exceeds them is ended by the platform.

The client address is the connection's peer address (`falak serve`) or Cloudflare's `CF-Connecting-IP` header (Workers). A runtime MUST NOT take it from `X-Forwarded-For` or any other header a client can set.

### 7.2 Public keys

A runtime that issues its own tokens (`/v1/auth/*`) publishes the public keys that verify them at `GET /.well-known/jwks.json` as a JSON Web Key Set (Ed25519, `kty` `OKP`). The response contains no private key material and may be cached for five minutes. Another service verifies this app's tokens by fetching the set, caching it for ten minutes, and refetching at most once every 30 seconds when a token names an unknown `kid`.

---

## 8. Complete Notebook Validation App API Reference

Below is the complete catalog of requests and responses for the **Digital Notebook** validation application (`examples/notebook/`). Dev5 can directly implement SDK bindings, client fixtures, and smoke test assertions against these schemas.

### 8.1 Data Model Overview
* **Notebook (`notebooks`):**
  * `id`: `uuid` (Primary Key)
  * `title`: `text` (Required, max length 120)
  * `description`: `text` (Optional)
  * `owner_id`: `uuid` (Required, indexed, references Principal)
  * `created_at`: `timestamptz` (Auto UTC)
  * `updated_at`: `timestamptz` (Auto UTC)
  * `version`: `int64` (System version)
* **Note (`notes`):**
  * `id`: `uuid` (Primary Key)
  * `notebook_id`: `uuid` (Required, indexed, references `notebooks.id`)
  * `title`: `text` (Required, max length 200)
  * `body`: `text` (Optional)
  * `pinned`: `bool` (Default `false`)
  * `archived`: `bool` (Default `false`)
  * `owner_id`: `uuid` (Required, indexed)
  * `created_at`: `timestamptz` (Auto UTC)
  * `updated_at`: `timestamptz` (Auto UTC)
  * `version`: `int64` (System version)

---

### 8.2 Notebook Operations

#### 1. Create a Notebook
**Request:**
```http
POST /v1/notebooks HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8
Idempotency-Key: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d

{
  "title": "Work Projects",
  "description": "Notebook for engineering design and plans"
}
```

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8
ETag: W/"1"
Location: /v1/notebooks/018f6c4a-67a2-7b81-9b1e-355f309a4d88
X-Request-Id: req_01h8abc123

{
  "id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Work Projects",
  "description": "Notebook for engineering design and plans",
  "owner_id": "018f6c40-1111-7000-8000-000000000001",
  "created_at": "2026-11-15T14:00:00.000Z",
  "updated_at": "2026-11-15T14:00:00.000Z",
  "version": 1
}
```

---

#### 2. List Notebooks (Paginated)
**Request:**
```http
GET /v1/notebooks?page[size]=10&sort=-created_at HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: private, no-cache, no-store, must-revalidate
X-Request-Id: req_01h8abc124

{
  "data": [
    {
      "id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
      "title": "Work Projects",
      "description": "Notebook for engineering design and plans",
      "owner_id": "018f6c40-1111-7000-8000-000000000001",
      "created_at": "2026-11-15T14:00:00.000Z",
      "updated_at": "2026-11-15T14:00:00.000Z",
      "version": 1
    }
  ],
  "meta": {
    "page_size": 10,
    "has_more": false,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

#### 3. Get Notebook by ID
**Request:**
```http
GET /v1/notebooks/018f6c4a-67a2-7b81-9b1e-355f309a4d88 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
ETag: W/"1"
Cache-Control: private, no-cache, no-store, must-revalidate
X-Request-Id: req_01h8abc125

{
  "id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Work Projects",
  "description": "Notebook for engineering design and plans",
  "owner_id": "018f6c40-1111-7000-8000-000000000001",
  "created_at": "2026-11-15T14:00:00.000Z",
  "updated_at": "2026-11-15T14:00:00.000Z",
  "version": 1
}
```

---

#### 4. Update Notebook (Optimistic Lock)
**Request:**
```http
PATCH /v1/notebooks/018f6c4a-67a2-7b81-9b1e-355f309a4d88 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8
If-Match: W/"1"

{
  "title": "Work & Research Projects"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
ETag: W/"2"
X-Request-Id: req_01h8abc126

{
  "id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Work & Research Projects",
  "description": "Notebook for engineering design and plans",
  "owner_id": "018f6c40-1111-7000-8000-000000000001",
  "created_at": "2026-11-15T14:00:00.000Z",
  "updated_at": "2026-11-15T14:05:00.000Z",
  "version": 2
}
```

---

#### 5. Delete Notebook
**Request:**
```http
DELETE /v1/notebooks/018f6c4a-67a2-7b81-9b1e-355f309a4d88 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
```

**Response:**
```http
HTTP/1.1 204 No Content
X-Request-Id: req_01h8abc127
```

---

### 8.3 Note Operations

#### 6. Create Note in a Notebook
**Request:**
```http
POST /v1/notes HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8
Idempotency-Key: c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f

{
  "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Storage Driver Plan",
  "body": "Implement SQLite WAL mode and SQLx connection pooling."
}
```

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8
ETag: W/"1"
Location: /v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99
X-Request-Id: req_01h8abc128

{
  "id": "018f6c55-88b3-7c92-8a2f-466a410b5e99",
  "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Storage Driver Plan",
  "body": "Implement SQLite WAL mode and SQLx connection pooling.",
  "pinned": false,
  "archived": false,
  "owner_id": "018f6c40-1111-7000-8000-000000000001",
  "created_at": "2026-11-15T14:10:00.000Z",
  "updated_at": "2026-11-15T14:10:00.000Z",
  "version": 1
}
```

---

#### 7. Filter & List Notes with Keyset Pagination
**Request:**
```http
GET /v1/notes?filter[notebook_id]=018f6c4a-67a2-7b81-9b1e-355f309a4d88&filter[archived]=false&sort=-pinned,-created_at&page[size]=2 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: private, no-cache, no-store, must-revalidate
X-Request-Id: req_01h8abc129

{
  "data": [
    {
      "id": "018f6c55-88b3-7c92-8a2f-466a410b5e99",
      "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
      "title": "Storage Driver Plan",
      "body": "Implement SQLite WAL mode and SQLx connection pooling.",
      "pinned": false,
      "archived": false,
      "owner_id": "018f6c40-1111-7000-8000-000000000001",
      "created_at": "2026-11-15T14:10:00.000Z",
      "updated_at": "2026-11-15T14:10:00.000Z",
      "version": 1
    }
  ],
  "meta": {
    "page_size": 2,
    "has_more": false,
    "next_cursor": null,
    "prev_cursor": null
  }
}
```

---

#### 8. Custom Command: Pin Note
Commands are explicit domain mutations defined in `commands/*.yaml`.
**Request:**
```http
POST /v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99/pin HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8
Idempotency-Key: e5f6a7b8-1c2d-3e4f-5a6b-7c8d9e0f1a2b

{}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
ETag: W/"2"
X-Request-Id: req_01h8abc130

{
  "id": "018f6c55-88b3-7c92-8a2f-466a410b5e99",
  "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Storage Driver Plan",
  "body": "Implement SQLite WAL mode and SQLx connection pooling.",
  "pinned": true,
  "archived": false,
  "owner_id": "018f6c40-1111-7000-8000-000000000001",
  "created_at": "2026-11-15T14:10:00.000Z",
  "updated_at": "2026-11-15T14:12:00.000Z",
  "version": 2
}
```

---

#### 9. Custom Command: Archive Note
**Request:**
```http
POST /v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99/archive HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8
Idempotency-Key: f6a7b8c9-2d3e-4f5a-6b7c-8d9e0f1a2b3c

{}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
ETag: W/"3"
X-Request-Id: req_01h8abc131

{
  "id": "018f6c55-88b3-7c92-8a2f-466a410b5e99",
  "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Storage Driver Plan",
  "body": "Implement SQLite WAL mode and SQLx connection pooling.",
  "pinned": true,
  "archived": true,
  "owner_id": "018f6c40-1111-7000-8000-000000000001",
  "created_at": "2026-11-15T14:10:00.000Z",
  "updated_at": "2026-11-15T14:15:00.000Z",
  "version": 3
}
```

---

#### 10. Delete Note
**Request:**
```http
DELETE /v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
```

**Response:**
```http
HTTP/1.1 204 No Content
X-Request-Id: req_01h8abc132
```

---

### 8.4 Error Responses (Problem Details Catalog)

#### 400 Bad Request (Input Validation Failure)
**Request:**
```http
POST /v1/notes HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8

{
  "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": ""
}
```

**Response:**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json; charset=utf-8
X-Request-Id: req_01h8abc133

{
  "type": "https://falak.me/errors/invalid-input",
  "title": "Bad Request",
  "status": 400,
  "detail": "Request validation failed.",
  "code": "invalid_input",
  "instance": "/v1/notes",
  "request_id": "req_01h8abc133",
  "invalid_params": [
    {
      "name": "title",
      "reason": "String must be at least 1 character in length",
      "code": "value_too_short"
    }
  ]
}
```

---

#### 401 Unauthorized (Missing or Invalid Token)
**Request:**
```http
GET /v1/notes HTTP/1.1
Host: api.notebook.local
```

**Response:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json; charset=utf-8
WWW-Authenticate: Bearer error="invalid_token", error_description="Bearer token is missing or malformed"
X-Request-Id: req_01h8abc134

{
  "type": "https://falak.me/errors/unauthenticated",
  "title": "Unauthorized",
  "status": 401,
  "detail": "Authentication is required.",
  "code": "unauthenticated",
  "instance": "/v1/notes",
  "request_id": "req_01h8abc134"
}
```

---

#### 403 Forbidden (Policy Denial)
When an authenticated caller lacks permissions to execute an action (e.g. creating notes in an archived notebook):
**Request:**
```http
POST /v1/notes HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_b>
Content-Type: application/json; charset=utf-8

{
  "notebook_id": "018f6c4a-67a2-7b81-9b1e-355f309a4d88",
  "title": "Intrusion Attempt"
}
```

**Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json; charset=utf-8
X-Request-Id: req_01h8abc135

{
  "type": "https://falak.me/errors/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "Not permitted.",
  "code": "forbidden",
  "instance": "/v1/notes",
  "request_id": "req_01h8abc135"
}
```

---

#### 404 Not Found (Isolation Masking)
When User B attempts to access a note owned by User A:
**Request:**
```http
GET /v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_b>
```

**Response:**
```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json; charset=utf-8
X-Request-Id: req_01h8abc136

{
  "type": "https://falak.me/errors/not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "Not found.",
  "code": "not_found",
  "instance": "/v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99",
  "request_id": "req_01h8abc136"
}
```
*(Notice: Never returns 403; returns 404 so existence is not revealed).*

---

#### 412 Precondition Failed (Optimistic Lock Collision)
**Request:**
```http
PATCH /v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99 HTTP/1.1
Host: api.notebook.local
Authorization: Bearer <token_user_a>
Content-Type: application/json; charset=utf-8
If-Match: W/"1"

{
  "title": "Stale Title Edit"
}
```

**Response:**
```http
HTTP/1.1 412 Precondition Failed
Content-Type: application/problem+json; charset=utf-8
X-Request-Id: req_01h8abc137

{
  "type": "https://falak.me/errors/precondition-failed",
  "title": "Precondition Failed",
  "status": 412,
  "detail": "Resource was modified by another operation. Current version is 3.",
  "code": "precondition_failed",
  "instance": "/v1/notes/018f6c55-88b3-7c92-8a2f-466a410b5e99",
  "request_id": "req_01h8abc137"
}
```

---

#### 429 Too Many Requests (Rate Limit Quota Exceeded)
**Response:**
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/problem+json; charset=utf-8
Retry-After: 30
RateLimit-Limit: 100
RateLimit-Remaining: 0
RateLimit-Reset: 30
X-Request-Id: req_01h8abc138

{
  "type": "https://falak.me/errors/rate-limited",
  "title": "Too Many Requests",
  "status": 429,
  "detail": "Too many requests. Please retry later.",
  "code": "rate_limited",
  "instance": "/v1/notes",
  "request_id": "req_01h8abc138"
}
```
