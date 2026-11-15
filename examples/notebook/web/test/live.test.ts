// Runs the generated client and the sign-in session against a real server.
// Skipped unless FALAK_URL is set; `scripts/smoke/notebook.sh` sets it.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FalakError } from "@falak/sdk";

import { createClient } from "../src/falak.generated.ts";
import { Session, type Storage } from "../src/session.ts";

const base = process.env["FALAK_URL"];

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

describe("generated client against a live server", { skip: base === undefined }, () => {
  const url = base ?? "";
  const session = new Session({
    fetch: (path, init) => fetch(url + String(path), init),
    storage: memoryStorage(),
  });
  const api = createClient({ baseUrl: url, token: async () => (await session.accessToken()) ?? "" });
  const email = `web-${Date.now()}@example.com`;

  it("signs up and signs in", async () => {
    await session.signUp(email, "a long passphrase here");
    assert.equal(session.signedIn, true);
    assert.ok(await session.accessToken());
  });

  it("creates, lists, filters, updates, archives and deletes", async () => {
    const book = await api.notebooks.create({ title: "Work" });
    assert.equal(book.version, 1);

    const a = await api.notes.create({ title: "A", notebook_id: book.id });
    const b = await api.notes.create({ title: "B", body: "text", notebook_id: book.id });
    assert.equal(b.body, "text");

    const all = await api.notes.list({ filter: { notebook_id: book.id }, sort: ["title"] });
    assert.deepEqual(all.data.map((n) => n.title), ["A", "B"]);

    const updated = await api.notes.update(a.id, { title: "A2" }, { ifMatch: a.version });
    assert.equal(updated.title, "A2");
    assert.equal(updated.version, a.version + 1);

    // A stale version is a typed conflict.
    const conflict = await api.notes.update(a.id, { title: "x" }, { ifMatch: a.version }).catch((e: unknown) => e);
    assert.ok(conflict instanceof FalakError);
    assert.equal(conflict.isVersionConflict, true);

    const archived = await api.notes.archiveNote(b.id);
    assert.equal(archived.archived, true);
    const visible = await api.notes.list({ filter: { notebook_id: book.id, archived: false } });
    assert.deepEqual(visible.data.map((n) => n.id), [a.id]);
    const restored = await api.notes.restoreNote(b.id);
    assert.equal(restored.archived, false);

    await api.notes.delete(a.id, { ifMatch: updated.version });
    const gone = await api.notes.get(a.id).catch((e: unknown) => e);
    assert.ok(gone instanceof FalakError);
    assert.equal(gone.status, 404);
  });

  it("follows cursors across pages", async () => {
    const book = await api.notebooks.create({ title: "Many" });
    for (let i = 0; i < 5; i++) await api.notes.create({ title: `n${i}`, notebook_id: book.id });
    const seen: string[] = [];
    for await (const n of api.notes.all({ filter: { notebook_id: book.id }, sort: ["title"], pageSize: 2 })) {
      seen.push(n.title);
    }
    assert.deepEqual(seen, ["n0", "n1", "n2", "n3", "n4"]);
  });

  it("reports field errors from the server", async () => {
    const err = await api.notes.create({ title: "", notebook_id: "not-a-uuid" }).catch((e: unknown) => e);
    assert.ok(err instanceof FalakError);
    assert.equal(err.status, 400);
  });

  it("is refused after signing out", async () => {
    await session.logOut();
    assert.equal(session.signedIn, false);
    const err = await api.notes.list().catch((e: unknown) => e);
    assert.ok(err instanceof FalakError);
    assert.equal(err.status, 401);
  });
});
