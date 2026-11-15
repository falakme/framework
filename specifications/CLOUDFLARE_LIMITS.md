# Cloudflare Workers and D1 limits

Task T0.7. Input to `DRIVER_SPECIFICATION.md` (T0.5) and the capability profile for the D1 driver.

**Date checked:** 2026-11-15
**Checked by:** Dev3
**Plan assumed:** Workers Paid. Free-plan values are shown where they differ, because they decide whether a hobby deployment works.

Every value cites the vendor page it came from. Cloudflare changes these numbers; re-check before each phase gate and when a limit in this file causes a build failure.

## Sources

| Id | Page | Page last updated (per vendor) |
| :-- | :-- | :-- |
| W | [Workers: Limits](https://developers.cloudflare.com/workers/platform/limits/) | 2026-11-13 |
| D | [D1: Limits](https://developers.cloudflare.com/d1/platform/limits/) | 2026-10-30 |
| DA | [D1 Worker API: D1Database](https://developers.cloudflare.com/d1/worker-api/d1-database/) | 2026-06-22 |
| RR | [D1: Global read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) | 2026-08-10 |
| SQL | [D1: SQL statements](https://developers.cloudflare.com/d1/sql-api/sql-statements/) | not shown on page |

## Workers runtime limits

| Limit | Free | Paid | Source |
| :-- | :-- | :-- | :-- |
| CPU time per HTTP request | 10 ms | 5 min (default 30 s) | W, CPU time |
| CPU time per Cron Trigger | 10 ms | 30 s (interval under 1 h), 15 min (1 h or more) | W, CPU time |
| Memory per isolate (JS heap and WASM) | 128 MB | 128 MB | W, Memory |
| Wall time, HTTP request | no limit while client connected | no limit while client connected | W, Duration |
| Wall time, Cron Trigger, Queue consumer, Durable Object alarm | 15 min | 15 min | W, Duration |
| `waitUntil()` extension after response | 30 s | 30 s | W, Duration |
| Subrequests per invocation (includes D1, KV, R2) | 50 | 10,000 (configurable up to 10 M) | W, Subrequests |
| Simultaneous connections waiting for headers | 6 | 6 | W, Simultaneous open connections |
| Worker size (uncompressed bundle, WASM included) | 64 MiB | 64 MiB | W, Worker size |
| Worker startup time (global scope) | 1 s | 1 s | W, Worker startup time |
| Environment variables (secrets and text) per Worker | 64 | 128 | W, Environment variables |
| Environment variable size | 5 KB | 5 KB | W, Environment variables |
| Requests per day | 100,000 | no limit | W, Daily requests |
| Cron Triggers per account | 5 | 250 | W, Account plan limits |
| Workers per account | 100 | 500 | W, Account plan limits |
| Request header size (total) | 128 KB | 128 KB | W, Request and response limits |
| URL size | 16 KB | 16 KB | W, Request and response limits |
| Request body size | set by the zone plan: 100 MB (Free, Pro), 200 MB (Business), up to 5 GB (Enterprise) | same | W, Request and response limits |
| Log data per request | 256 KB | 256 KB | W, Log size |

## D1 limits

| Limit | Free | Paid | Source |
| :-- | :-- | :-- | :-- |
| Maximum database size | 500 MB | 10 GB (cannot be raised) | D |
| Databases per account | 10 | 1,000,000 (first 100,000 included, then $0.10 per database per month) | D |
| Storage per account | 5 GB | 1 TB (raisable on request) | D |
| Queries per Worker invocation | 50 | 1,000 | D |
| Time Travel (point-in-time recovery) | 7 days | 30 days | D |
| Time Travel restores | 10 per 10 min per database | 10 per 10 min per database | D |
| Columns per table | 100 | 100 | D |
| String, `BLOB` or row size | 2,000,000 bytes | 2,000,000 bytes | D |
| SQL statement length | 100,000 bytes | 100,000 bytes | D |
| Bound parameters per query | 100 | 100 | D |
| Arguments per SQL function | 32 | 32 | D |
| `LIKE` or `GLOB` pattern length | 50 bytes | 50 bytes | D |
| SQL query duration | 30 s | 30 s (also bounds a whole `batch()` call) | D, footnote 3 |
| Query result size | 50 MB (applies from 2026-11-04) | 50 MB | D, footnote 5 |
| Databases bindable to one Worker script | about 5,000 | about 5,000 | D, footnote 2 |
| Simultaneous D1 connections per invocation | 6 | 6 | D, FAQ |

## D1 behaviour that shapes the driver

| Behaviour | Detail | Source |
| :-- | :-- | :-- |
| No interactive transactions | D1 runs in auto-commit. The only multi-statement atomic unit is `batch()`. | DA, `batch()` |
| `batch()` is atomic | Statements run in order, not in parallel, as one SQL transaction. A failed statement rolls back the whole batch. | DA, `batch()` |
| `batch()` counts as one query | It counts once against the queries-per-invocation limit. Per-statement limits (100 KB, 100 parameters) still apply to each statement inside it. | D, Batch limits |
| One writer thread per database | Each database processes one query at a time. Throughput is about `1 / average query time`, less per-request overhead. | D, FAQ |
| Overload | A full queue returns an "overloaded" error. | D, FAQ |
| Large writes must be chunked | A single statement changing hundreds of thousands of rows can exceed limits. Process about 1,000 rows at a time. | D, FAQ |
| Read replicas need the Sessions API | Without `withSession`, every query goes to the primary. A session gives sequential consistency and returns a bookmark (`getBookmark()`) that the next request can pass to `withSession`. | RR |
| Foreign key enforcement can be deferred | `PRAGMA defer_foreign_keys = on` defers checks to the end of the transaction. This is the documented tool for migrations and table rebuilds (T3.8). `ON DELETE CASCADE` still runs. | SQL |

## What this means for the design

These are Dev3's reading of the limits above, not vendor statements. Dev1 decides whether they change ARCHITECTURE.md.

1. **Capability profile for D1** (ARCHITECTURE §4.4): interactive transactions `no`; atomic batch `yes`; row-level security `no`; maximum bound parameters `100`; maximum statement size `100,000 bytes`; maximum row size `2,000,000 bytes`; maximum result size `50 MB`; maximum database size `10 GB`; maximum queries per request `1,000`.
2. **The 100 bound-parameter limit is the tightest constraint.** A multi-row insert, an `IN (...)` filter or a policy predicate with many parameters can hit it. The Query AST compiler (T1.5) needs a per-driver parameter budget, and the build-time validator (T2.1) should reject a statement template that exceeds it. A bulk write splits into several statements inside one `batch()`.
3. **Read-then-write commands** (T2.2) must compile to one conditional `batch()` guarded by a version column. There is no way to hold a read open across a write.
4. **The size budget is not set by Cloudflare.** The Worker limit is 64 MiB uncompressed, but startup must finish in 1 s, so a smaller bundle is better. The budget for T2.8 and T0.8 should be set from the T0.8 measurement, not from this limit.
5. **Startup time (1 s) bounds IR loading.** The WASM core must not parse a large IR in global scope. Load the compiled IR lazily or keep it small. Vendor guidance names large schemas at top level as a common cause of startup failure.
6. **Free plan is unusable for real traffic.** 10 ms CPU, 50 subrequests and 500 MB per database. Treat Workers Paid as the minimum for the edge runtime and say so in the quickstart.
7. **Time Travel gives D1 a built-in 30-day restore** on Paid (7 on Free). It reduces what T3.7 and T6.3 must build for D1, but it is limited to 10 restores per 10 minutes per database.
8. **Per-tenant databases (`database` tenancy, T3.9) fit D1's design.** The vendor recommends many small databases. One Worker script can bind about 5,000, so a tenant count above that needs routing through Workers for Platforms or dynamic lookup. This is open and needs a decision before T3.9.
9. **Edge relay (T5.4)** has 15 minutes of wall time per Cron Trigger or Queue consumer invocation, and Cron CPU time of 30 s under hourly intervals.
10. **Request body limit depends on the zone plan.** Large uploads must go straight to object storage through presigned URLs (T3.11), not through the Worker.

11. **Integers above 2^53 − 1 cannot be passed to D1 exactly from a Worker.** The `workers-rs` 0.9 binding sends numbers as JavaScript doubles (`D1Type::Integer` is `i32`, and larger values go through `f64`). The D1 driver refuses such a value with `storage_integer_range` instead of rounding it. Money in minor units stays exact up to 9,007,199,254,740,991 (about 90 trillion units of a two-decimal currency). Phase 8 must decide whether that is enough on D1 or whether the ledger runs on PostgreSQL only. This was read from the `workers-rs` source, not tested against a live database.

## Open items

- The pricing of D1 (rows read and written) was not checked. It does not limit correctness, but it affects the cost of the `database` tenancy mode. Check before T3.9.
- Durable Objects, Queues, KV and R2 limits were not checked. Check Queues and R2 when T5.4 and T3.11 start.
- The Sessions API behaviour with batch writes (does a write return a bookmark) was not tested. T2.6 must verify it against a real database.
