import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FalakClient, FalakError, Resource, buildQuery } from "../src/index.ts";

interface Note {
  id: string;
  title: string;
  version: number;
}

type Call = { url: string; method: string; headers: Record<string, string>; body: unknown };

/** A fake `fetch` that plays back responses and records what was sent. */
function fake(...replies: Array<Response | Error>) {
  const calls: Call[] = [];
  const impl: typeof fetch = async (input, init) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: { ...(init?.headers as Record<string, string>) },
      body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
    });
    const next = replies.shift();
    if (!next) throw new Error("no reply left");
    if (next instanceof Error) throw next;
    return next;
  };
  return { calls, impl };
}

const json = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });

const problem = (status: number, code: string, extra: object = {}, headers: HeadersInit = {}) =>
  new Response(JSON.stringify({ status, code, detail: `problem ${code}`, ...extra }), {
    status,
    headers: { "Content-Type": "application/problem+json", ...headers },
  });

function notes(f: ReturnType<typeof fake>, extra: Partial<ConstructorParameters<typeof FalakClient>[0]> = {}) {
  const client = new FalakClient({
    baseUrl: "http://api.test/",
    token: "tok",
    fetch: f.impl,
    newIdempotencyKey: (() => {
      let n = 0;
      return () => `key-${++n}`;
    })(),
    ...extra,
  });
  return new Resource<Note, { title: string }, { title?: string }>(client, "note", "notes");
}

describe("requests", () => {
  it("sends the bearer token and reads the record", async () => {
    const f = fake(json({ id: "1", title: "a", version: 1 }, { headers: { ETag: 'W/"1"' } }));
    const note = await notes(f).get("1");
    assert.equal(note.title, "a");
    assert.equal(f.calls[0]?.url, "http://api.test/v1/notes/1");
    assert.equal(f.calls[0]?.headers["Authorization"], "Bearer tok");
  });

  it("asks a token function for a fresh token each time", async () => {
    let n = 0;
    const f = fake(json({}), json({}));
    const r = notes(f, { token: () => `t${++n}` });
    await r.get("1");
    await r.get("2");
    assert.deepEqual(
      f.calls.map((c) => c.headers["Authorization"]),
      ["Bearer t1", "Bearer t2"],
    );
  });

  it("adds an idempotency key to writes and not to reads", async () => {
    const f = fake(json({}), json({}), json({}));
    const r = notes(f);
    await r.get("1");
    await r.create({ title: "x" });
    await r.update("1", { title: "y" }, { ifMatch: 3 });
    assert.equal(f.calls[0]?.headers["Idempotency-Key"], undefined);
    assert.equal(f.calls[1]?.headers["Idempotency-Key"], "key-1");
    assert.equal(f.calls[2]?.headers["If-Match"], 'W/"3"');
    assert.equal(f.calls[2]?.method, "PATCH");
  });

  it("lets a caller turn idempotency keys off", async () => {
    const f = fake(json({}));
    await notes(f).create({ title: "x" }, { idempotent: false });
    assert.equal(f.calls[0]?.headers["Idempotency-Key"], undefined);
  });

  it("handles 204 from delete", async () => {
    const f = fake(new Response(null, { status: 204 }));
    await notes(f).delete("1", { ifMatch: 2 });
    assert.equal(f.calls[0]?.method, "DELETE");
    assert.equal(f.calls[0]?.headers["If-Match"], 'W/"2"');
  });
});

describe("errors", () => {
  it("raises a typed error with the problem fields", async () => {
    const f = fake(
      problem(400, "validation_failed", {
        request_id: "req_1",
        invalid_params: [{ name: "title", reason: "Required", code: "required" }],
      }),
    );
    const err = await notes(f)
      .create({ title: "" })
      .catch((e: unknown) => e);
    assert.ok(err instanceof FalakError);
    assert.equal(err.status, 400);
    assert.equal(err.code, "validation_failed");
    assert.equal(err.requestId, "req_1");
    assert.deepEqual(err.fieldErrors(), { title: "Required" });
    assert.equal(err.retryable, false);
  });

  it("flags a stale version", async () => {
    const f = fake(problem(412, "precondition_failed"));
    const err = (await notes(f)
      .update("1", { title: "z" }, { ifMatch: 1 })
      .catch((e: unknown) => e)) as FalakError;
    assert.equal(err.isVersionConflict, true);
  });

  it("copes with a non-JSON error page", async () => {
    const f = fake(new Response("<html>bad gateway</html>", { status: 502 }));
    const err = (await notes(f)
      .get("1")
      .catch((e: unknown) => e)) as FalakError;
    assert.equal(err.status, 502);
    assert.equal(err.code, "unknown_error");
  });
});

describe("retries", () => {
  it("retries a busy server and reuses the idempotency key", async () => {
    const f = fake(problem(503, "service_unavailable", {}, { "Retry-After": "0" }), json({ id: "1" }));
    await notes(f).create({ title: "x" });
    assert.equal(f.calls.length, 2);
    assert.equal(f.calls[0]?.headers["Idempotency-Key"], "key-1");
    assert.equal(f.calls[1]?.headers["Idempotency-Key"], "key-1");
  });

  it("retries a dropped connection for a read", async () => {
    const f = fake(new TypeError("fetch failed"), json({ id: "1" }));
    await notes(f, { maxRetries: 1 }).get("1");
    assert.equal(f.calls.length, 2);
  });

  it("does not retry a write that has no idempotency key", async () => {
    const f = fake(problem(503, "service_unavailable", {}, { "Retry-After": "0" }), json({}));
    await assert.rejects(notes(f).create({ title: "x" }, { idempotent: false }));
    assert.equal(f.calls.length, 1);
  });

  it("gives up after maxRetries", async () => {
    const r503 = () => problem(503, "service_unavailable", {}, { "Retry-After": "0" });
    const f = fake(r503(), r503(), r503());
    await assert.rejects(notes(f).get("1"));
    assert.equal(f.calls.length, 3);
  });

  it("does not retry a 400", async () => {
    const f = fake(problem(400, "validation_failed"), json({}));
    await assert.rejects(notes(f).get("1"));
    assert.equal(f.calls.length, 1);
  });
});

describe("pagination and queries", () => {
  const page = (ids: string[], next: string | null) =>
    json({
      data: ids.map((id) => ({ id, title: id, version: 1 })),
      meta: { page_size: 2, has_more: next !== null, next_cursor: next, prev_cursor: null },
    });

  it("follows cursors until the end", async () => {
    const f = fake(page(["a", "b"], "c1"), page(["c", "d"], "c2"), page(["e"], null));
    const seen: string[] = [];
    for await (const n of notes(f).all({ pageSize: 2 })) seen.push(n.id);
    assert.deepEqual(seen, ["a", "b", "c", "d", "e"]);
    assert.match(f.calls[1]?.url ?? "", /page%5Bafter%5D=c1/);
    assert.match(f.calls[0]?.url ?? "", /page%5Bsize%5D=2/);
  });

  it("builds filters, sort, fields and include", () => {
    const q = buildQuery<Note>("note", {
      filter: { title: { like: "%x%" }, version: { in: [1, 2] } },
      sort: ["-created_at", "id"],
      fields: ["id", "title"],
      include: ["notebook"],
    });
    const p = new URLSearchParams(q);
    assert.equal(p.get("filter[title][like]"), "%x%");
    assert.equal(p.get("filter[version][in]"), "1,2");
    assert.equal(p.get("sort"), "-created_at,id");
    assert.equal(p.get("fields[note]"), "id,title");
    assert.equal(p.get("include"), "notebook");
  });

  it("writes a plain equality filter and null", () => {
    const p = new URLSearchParams(buildQuery<{ archived: boolean; body: string }>("note", { filter: { archived: false, body: null } }));
    assert.equal(p.get("filter[archived]"), "false");
    assert.equal(p.get("filter[body]"), "null");
  });
});
