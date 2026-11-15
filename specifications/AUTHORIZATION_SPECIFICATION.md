# Authorization Specification

* **Status:** Frozen 1.0 for stage 1 (ownership, roles, authentication) (2026-11-15, ADR-0007 and ADR-0009). Stages 2 and 3 are additions and are not frozen yet.
* **Owner:** Dev4. Compiler behaviour: Dev1 (`falak-core::policy`, `falak-core::sql`).
* **Scope:** who may do what to which rows. The YAML syntax is in `SCHEMA_SPECIFICATION.md` §6; this document says what the keys mean and what the runtime MUST do. Stage 2 (attributes, field masks) and stage 3 (relationships) extend it without changing anything here.

Words in capitals (MUST, MUST NOT, SHOULD) are used in their usual specification sense.

---

## 1. Principles

1. **Default deny.** An action is allowed only if a rule grants it. An entity with no policy file permits nothing. A request with no verified principal is denied for every entity, unless a rule says `authenticated` (which still needs a principal).
2. **The caller comes from a verified token.** A principal is built only from a verified access token (`falak-auth::token::Verifier`). A user id, role or tenant in a header, query string or body MUST NOT be used as identity.
3. **Rules add.** An action is allowed if **any** rule that lists it is satisfied. There are no deny rules in stage 1.
4. **Policy is data in the IR.** The runtime reads rules from the IR. It does not read YAML, and it does not accept policy from a request.
5. **Fail closed.** Any state the runtime does not understand (an unknown rule kind, an `owner` rule on an entity with no owner field, a missing principal) is a denial.
6. **No existence leaks.** A row the caller may not read is indistinguishable from a row that does not exist: `404`, never `403`.

## 2. Vocabulary

| Term | Meaning |
| :-- | :-- |
| Principal | The verified caller: `subject` (the user id), optional `tenant`, and `roles`. |
| Subject | The user id string. Under local identity it is a lowercase hyphenated UUID, which is also how an `owner` field stores it. |
| Action | One of `read` (get and list), `create`, `update`, `delete`. |
| Rule | `{ id, actions, allow }`. |
| Owner field | The entity's `owner:` field. Holds the id of the user who owns the row. |

## 3. Conditions (`allow`)

A rule has exactly one condition.

| Condition | Satisfied when | Effect on the query |
| :-- | :-- | :-- |
| `owner: true` | The entity has an owner field (the compiler rejects the policy otherwise). | The runtime adds `owner_field = <subject>` to the query. Rows owned by others are not returned, updated or deleted. |
| `role: <name>` | `<name>` is in the principal's roles. | No row condition. |
| `authenticated: true` | A verified principal exists. | No row condition. |

Role names are matched exactly and case-sensitively against the `roles` claim.

## 4. Decision procedure

For one entity, one action and one principal:

```text
no principal                                  -> Denied
any matching rule with `authenticated`        -> Unrestricted
any matching rule with `role` the principal has -> Unrestricted
any matching rule with `owner`                -> OwnedBy(subject)
otherwise                                     -> Denied
```

"Matching" means the rule lists the action. An unrestricted grant beats an owner grant, so an admin with a `role` rule sees every row even though the owner rule also applies.

`Denied` MUST NOT run any query. `Unrestricted` and `OwnedBy` are applied by the SQL builders as part of the statement, not by filtering results afterwards.

## 5. Action semantics

| Action | `Unrestricted` | `OwnedBy(subject)` |
| :-- | :-- | :-- |
| `read` | Get and list any row. | Get and list only owned rows. Others are `404` on get and absent from lists. |
| `create` | The caller sets the declared fields. The owner field is set by the server to the subject. | Same. |
| `create` with a client-supplied owner | `400`. | `400`. |
| `update` | Any row. The owner field MUST NOT change. | Only owned rows. Others are `404`. |
| `delete` | Any row. | Only owned rows. Others are `404`. |

A command is authorised as the action it performs: an `update` command needs `update`, a `delete` command needs `delete`, a `create` command needs `create`. The policy applies to the command's target row in the same statement that changes it.

Under `row` tenancy the tenant predicate (`tenant_id = <principal tenant>`) is ALWAYS added in addition to any rule and cannot be removed by one. A principal with no tenant on a tenant-scoped app is denied.

## 6. What the runtime MUST do

1. Verify the bearer token before reading the body.
2. Build the `Principal` only from verified claims.
3. Decide access before running any query for the entity.
4. Apply the decision in SQL (a predicate on the statement), so a caller never receives a row they may not read, even in an error message or a count.
5. Return `401` for no valid token, `404` for a row that is not visible, `403` only for an action the policy denies on an entity whose existence is not secret (for example `create` on an entity the caller may not create). Where a `403` would reveal that a specific row exists, use `404`.
6. Apply the same decision on every driver. The conformance suite (Phase 2) runs the isolation checks on SQLite, PostgreSQL and D1.
7. Never log a token, and never put a policy decision's internal detail (the matching rule's SQL) in a response. `falak policy explain` (T3.4) shows it to the developer.

## 7. Compiler checks

The compiler MUST reject (errors) a policy that:

* names an entity that does not exist;
* uses `owner` on an entity with no `owner:` field;
* lists an unknown action;
* has two rules with the same `id` in one file;
* has a condition other than the three above (stage 1).

It MUST warn when an entity has a policy that grants no `read`, because the data is then write-only.

## 8. Test requirements

Each of these has an automated test before the stage is accepted:

| Check | Expected |
| :-- | :-- |
| Entity with no policy file | Every action denied; no query runs. |
| No principal | Every action denied. |
| User A reads, updates, deletes a row owned by B | `404`; row unchanged. |
| User A lists | Only A's rows. |
| User A creates with `owner_id` set to B | `400`. |
| User A updates `owner_id` of own row | `400`; owner unchanged. |
| Role holder with a `role` rule reads all rows | All rows. |
| Role holder without the role | Same as any other user. |
| Token for another app, expired token, tampered token | `401`. |
| Identifier in a header claiming to be another user | Ignored. |
| Idempotency key reused by another user | Not replayed (scoped to the caller). |

`scripts/smoke/notebook.sh` (T1.17) runs the wrong-user checks end to end.

## 9. Not in stage 1

Attribute rules (`where`), field masks, relationship rules (`related`), deny rules, delegated access and time-limited grants. They are specified when their stages start (ADR-0007) and will add keys under `allow`; they will not change the meaning of the conditions above.

---

## 10. Stage 2: attribute conditions, field masks and side channels (ADR-0010)

Stage 2 adds two optional keys under `allow`. Both only narrow what a rule grants; neither changes the meaning of the stage 1 conditions.

```yaml
- id: reviewers_published
  actions: [read]
  allow:
    role: reviewer
    where: { status: published, owner_id: $subject, rank: { in: [1, 2] }, kind: { ne: secret } }
    fields: [title, status]
```

* `where` is a map of declared field to a value (equals), `$subject` (the caller), `{ in: [...] }` or `{ ne: value }`. Every condition must hold. The only variable is `$subject`. Encrypted, JSON and bytes fields cannot be compared. The compiler checks that fields exist and values fit their type.
* `fields` lists the declared fields the rule grants. Built-in fields (`id`, `version`, timestamps) are always granted. A rule without `fields` grants all of them.

**Decision.** Every satisfied rule that lists the action is a grant. A row is visible if any grant reaches it. A field of a visible row is returned only if a grant that reaches that row grants the field: otherwise it is `null`, decided in SQL per row. A request whose rules have neither `where` nor `fields` behaves exactly as in stage 1.

**Writes.** A write may set only fields that every satisfied rule grants (the most restrictive wins). On `create`, the new row must satisfy some grant's `where`, else `403`. On `update`, the row must be reachable before the change, and the row after the change must still be reachable: a change that would move a row out of the caller's reach does not happen and answers `404`.

**Side channels.** A field the caller cannot read on every row they can see MUST NOT be used to filter or sort, because the rows returned would reveal its values. Such a request is refused with the same `400` and the same wording as for a field that does not exist. Invisible rows are `404`. Relation traversal does not exist in v1; when it does it MUST apply the related entity's policy.

**Tenancy** (ADR-0003). Under `row` and `database` tenancy a caller with no tenant is denied. An entity that is tenant or owner scoped and has no policy file is a build error (`scoped_without_policy`). `tenancy: database` is not available with the `postgres` driver.

**PostgreSQL.** The same rules are compiled to row-level security as a second wall (see `falak-migrate::rls`): tenant policy `RESTRICTIVE`, one permissive policy per action, `FORCE ROW LEVEL SECURITY`, a runtime role `falak_app` with no ownership and no `BYPASSRLS`, and the caller read from `falak.subject`, `falak.tenant_id` and `falak.roles`, set per transaction. RLS works on rows only; field masks are the runtime's. Because PostgreSQL applies the `SELECT` policy to the rows an `UPDATE`, `DELETE` or `INSERT ... RETURNING` touches, the `SELECT` policy covers a rule granting any action; the runtime's own SQL still limits reads to rules that list `read`.
