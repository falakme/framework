# Schema Specification

* **Status:** Draft 1 (becomes frozen at the M2 exit; see ARCHITECTURE §5)
* **Owner:** Dev1
* **Scope:** the YAML files that describe an app, and how they compile to the IR. Policy semantics are in `AUTHORIZATION_SPECIFICATION.md`; driver behaviour in `DRIVER_SPECIFICATION.md`.
* **Machine-readable form:** the JSON Schemas in [`schemas/`](./schemas/). Where this document and a schema disagree, fix the document and the schema together. A worked example is in [`examples/minimal/`](./examples/minimal/).

Words in capitals (MUST, MUST NOT, SHOULD) are used in their usual specification sense.

---

## 1. Files

```text
my-app/
├── app.yaml                 # exactly one
├── entities/<name>.yaml     # one entity per file
├── policies/<name>.yaml     # one policy file per entity
├── commands/<name>.yaml     # one command per file
├── workflows/  events/  jobs/   # reserved; schemas arrive with M5 and M7
├── migrations/              # generated
└── falak.lock               # generated
```

The file name (without extension) MUST equal the `entity` or `command` it declares. A `policies/<name>.yaml` file MUST refer to an entity that exists. A directory that is reserved and not yet specified MUST be empty or absent; the compiler rejects files in it.

## 2. YAML subset

Falak reads YAML 1.2 using only the following features. The parser MUST reject, with a diagnostic at the offending position:

* duplicate mapping keys;
* anchors, aliases and merge keys (`&`, `*`, `<<`);
* explicit tags (`!!str`, `!custom`);
* more than one document in a file;
* non-string mapping keys;
* files larger than 256 KiB, nesting deeper than 16 levels, or any collection with more than 1,000 items.

Scalars follow the YAML 1.2 core schema: only `true` and `false` are booleans, so `yes`, `no`, `on` and `off` are strings. A value that must be a string and looks like another type (`1.0`, `null`, `0x10`) MUST be quoted. Unknown keys are errors everywhere. Every file MUST carry `schema_version`; the only value defined is `1`.

## 3. Names and limits

* Every identifier (entity, field, relation, command, role, rule id) matches `^[a-z][a-z0-9_]{0,62}$`. The app `name` is `^[a-z][a-z0-9_-]{1,39}$`.
* Reserved words MUST NOT be used as entity or field names: any SQL keyword the compiler lists in `RESERVED_WORDS`, and the built-in field names in §5.2.
* Limits per app: 200 entities, 100 fields per entity, 100 commands. Exceeding one is an error, not a warning.

## 4. `app.yaml`

| Key | Required | Meaning |
| :-- | :-- | :-- |
| `schema_version` | yes | `1` |
| `name` | yes | App identifier. Used for the audience in tokens and the Office registry. |
| `version` | yes | `MAJOR.MINOR.PATCH` of the app, recorded in the IR. |
| `description` | no | Up to 300 characters. |
| `tenancy` | no | `none` (default), `row` or `database`. See ADR-0003. |
| `trust_tier` | no | `standard` (default), `sensitive` or `high_assurance`. See ARCHITECTURE §4.6. |
| `drivers` | no | Drivers the app targets. The build checks the app against each one's capability profile and fails if any is insufficient. Default: all three. |
| `requires` | no | Capabilities needed beyond what the compiler infers (§10). |

## 5. Entities

### 5.1 Fields

```yaml
fields:
  title: { type: text, required: true, max_length: 200 }
```

| Attribute | Applies to | Meaning |
| :-- | :-- | :-- |
| `type` | all (required) | One of the types below. |
| `required` | all | The value MUST be present and not null. Default `false`. |
| `unique` | all | Unique across the entity (and within the tenant under `row` tenancy). |
| `indexed` | all | Create an index. Under `row` tenancy the index leads with `tenant_id`. |
| `default` | all | A literal of the field's type, or the generator `now` (`timestamptz`) or `uuid` (`uuid`). |
| `max_length` | `text`, `bytes` | Upper bound in characters or bytes. Default 4096 for `text`; MUST be set explicitly above that, up to 1,048,576. |
| `min`, `max` | `int64`, `decimal_minor` | Inclusive bounds. |
| `pii` | all | Personal data: masked in Studio by default and redacted in telemetry. |
| `encrypted` | `text`, `bytes`, `json` | Stored with envelope encryption using the tenant data key. An encrypted field cannot be filtered, sorted, indexed or declared `unique`. |
| `references` | `uuid` | `entity.field` this field points at. The compiler creates the foreign key where the driver supports it and always validates it on write. |

### 5.2 Types and storage

| Type | Meaning | PostgreSQL | SQLite and D1 |
| :-- | :-- | :-- | :-- |
| `uuid` | 128-bit identifier | `uuid` | `TEXT` (lowercase hyphenated) |
| `int64` | Signed 64-bit integer | `bigint` | `INTEGER` |
| `decimal_minor` | Money or exact quantity as an integer of minor units (cents). Never a float. | `bigint` | `INTEGER` |
| `text` | UTF-8 string, NFC-normalised on input | `text` | `TEXT` |
| `bool` | Boolean | `boolean` | `INTEGER` 0 or 1 |
| `timestamptz` | Instant in UTC, microsecond precision | `timestamptz` | `INTEGER` (microseconds since the epoch) |
| `bytes` | Binary | `bytea` | `BLOB` |
| `json` | JSON document | `jsonb` | `TEXT` |

There is no float type in v1. Fields of type `json` cannot be filtered in v1.

### 5.3 Built-in fields

Every entity has these fields. They MUST NOT be declared in the file.

| Field | Type | Behaviour |
| :-- | :-- | :-- |
| `id` | `uuid` | Primary key. Generated by the server; a client-supplied value is rejected. |
| `version` | `int64` | Starts at 1 and increases by one on every update. Exposed as the `ETag`; an update with a stale `If-Match` fails with `PreconditionFailed`. |
| `created_at` | `timestamptz` | Set on create. |
| `updated_at` | `timestamptz` | Set on every update. |
| `tenant_id` | `uuid` | Present only under `row` tenancy. Set from the verified request context; never accepted from input and never changed by an update. |
| `deleted_at` | `timestamptz` | Present only when `lifecycle.soft_delete` is true. Soft-deleted rows are invisible to every query. |

### 5.4 Other entity keys

* `table`: SQL table name. Default: the entity name pluralised by adding `s`. MUST be unique in the app.
* `owner`: the name of a `uuid` field holding the owning user's id. Required if any policy uses the `owner` rule. On create, the server sets it from the verified principal; on update it cannot be changed.
* `relations`: named relations. `belongs_to` says this entity holds `field` pointing at `entity`; `has_many` says `entity` holds `field` pointing back here. The two sides MUST agree.
* `admin`: Studio metadata: `label`, `list_columns`, `search_fields`. Every named field MUST exist and MUST NOT be `encrypted`.
* `lifecycle`: `soft_delete`, `retention_days` (rows older than this are deleted by a scheduled job) and `erasable` (the entity takes part in subject export and erasure).

## 6. Policies

A policy file lists rules. This specification covers stage 1 (ADR-0007): ownership, roles and authentication. Later stages add keys to `allow`; they do not change existing meaning.

```yaml
rules:
  - id: owner_full_access
    actions: [read, create, update, delete]
    allow: { owner: true }
```

* **Default deny.** An action that no rule grants is denied. An entity with no policy file permits nothing.
* **Rules add.** An action is allowed if **any** rule listing it is satisfied. There are no deny rules in stage 1.
* `allow` has exactly one condition: `owner: true` (the row's `owner` field equals the principal's subject), `role: <name>` (the principal holds that role) or `authenticated: true` (any verified principal).
* `read` covers get and list. For `owner`, the condition is added to the query as a predicate, so a caller never receives rows they do not own. A row that exists but is not visible returns `NotFound`.
* `create` with `owner: true` is allowed and sets the owner to the principal. `create` with a client-supplied owner is rejected.
* Under `row` tenancy the tenant predicate is always applied in addition to the rules and cannot be removed by any rule.
* The compiler MUST reject a policy that uses `owner` on an entity with no `owner` field, and MUST warn when an entity has a policy that grants no `read`.

## 7. Commands

Commands are explicit mutations beyond plain create, read, update and delete.

* `kind: create | update | delete` are declarative. `set` maps fields to a literal or to `$input.<name>`. `update` and `delete` MUST name a `target`: an `input` field of type `uuid` holding the row id.
* `kind: custom` calls a Rust handler registered under `handler` (ADR-0002). It MUST NOT carry `set` or `target`.
* Commands run with the caller's principal and are authorised by the entity policy for the action they perform (`update` for an `update` command and so on). A custom command is authorised for every entity it touches, through the policy-checked data layer.
* `input` fields are validated before anything runs. Unknown input fields are rejected.
* `idempotent: true` requires an `Idempotency-Key` header; a repeat with the same key and the same payload returns the stored result, and the same key with a different payload fails with `Conflict`. Keys are scoped to the caller and the command.

## 8. Reserved directories

`workflows/`, `events/` and `jobs/` are specified in the federation and compute phases. Until then they MUST be empty.

## 9. Compilation

`falak build` performs, in order:

1. **Parse** each file under §2, with exact file, line and column on every error.
2. **Validate** each file against its JSON Schema, then the cross-file rules: names and limits (§3), references and relations resolve, `owner` and policy consistency (§6), commands refer to existing entities and fields, `set` values match field types, `admin` fields exist.
3. **Resolve** built-in fields, tenancy fields and defaults.
4. **Infer requirements** (§10) and check them against every driver in `drivers`.
5. **Emit the IR** (`falak-contracts::ir`): entities with resolved fields, compiled SQL templates per driver, policy predicates and the OpenAPI document inputs.
6. **Hash** the IR's canonical JSON (struct fields in declaration order, entities and commands sorted by name, no insignificant whitespace, `content_hash` blank) with SHA-256, and record it in the IR and in `falak.lock`. Building the same sources twice MUST give the same hash, regardless of the order files are supplied in.

A diagnostic has a severity, a stable code, the file, line and column, a one-line message that says what is wrong, and a suggested fix where one exists. Warnings never fail a build; errors always do.

## 10. Inferred driver requirements

The compiler derives `requires` from the app and adds the explicit list:

| Source | Requirement |
| :-- | :-- |
| Any write | `atomic_batch` |
| Declarative `update` or `delete` | `atomic_batch` (compiled to a conditional batch on drivers without interactive transactions) |
| A `custom` command | `interactive_transactions`, unless the handler is declared batch-only |
| `tenancy: row` with a PostgreSQL target | `native_rls` for that target |
| `unique` or `references` | none (enforced by the database or by the write path) |
| `trust_tier: high_assurance` | `serializable_isolation` |

## 11. Versioning

* `schema_version` changes only for an incompatible change to these files. The compiler reads the current version and the one before it, and `falak upgrade` rewrites files.
* Adding an optional key is not a new version.

## 12. Open items

* The `RESERVED_WORDS` list is produced by T1.2.
* Workflow, event and job file formats are specified at M5 and M7.
* The stage 2 and 3 policy keys (`where`, `related`, field masks) are specified in `AUTHORIZATION_SPECIFICATION.md` when those stages start.
