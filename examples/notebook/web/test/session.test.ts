import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FalakError } from "@falak/sdk";

import { Session, type Storage } from "../src/session.ts";

function memoryStorage(): Storage & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

type Call = { path: string; body: Record<string, string> };

function server(handler: (path: string, body: Record<string, string>) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const impl: typeof fetch = async (input, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
    calls.push({ path: String(input), body });
    return handler(String(input), body);
  };
  return { calls, impl };
}

const tokens = (n: number, expiresIn = 900) =>
  new Response(JSON.stringify({ access_token: `a${n}`, refresh_token: `r${n}`, expires_in: expiresIn }), {
    status: 200,
  });

const problem = (status: number, code: string) =>
  new Response(JSON.stringify({ status, code, detail: code }), { status });

describe("Session", () => {
  it("logs in, keeps the access token in memory and the refresh token in storage", async () => {
    const storage = memoryStorage();
    const s = server(() => tokens(1));
    const session = new Session({ fetch: s.impl, storage });
    assert.equal(session.signedIn, false);
    await session.logIn("a@example.com", "pw");
    assert.equal(session.signedIn, true);
    assert.equal(await session.accessToken(), "a1");
    assert.equal(storage.data.get("falak.refresh"), "r1");
    assert.equal(JSON.stringify([...storage.data.values()]).includes("a1"), false, "access token is not stored");
  });

  it("raises the server's problem when login fails", async () => {
    const session = new Session({ fetch: server(() => problem(401, "invalid_credentials")).impl, storage: memoryStorage() });
    const err = await session.logIn("a@example.com", "bad").catch((e: unknown) => e);
    assert.ok(err instanceof FalakError);
    assert.equal(err.code, "invalid_credentials");
    assert.equal(session.signedIn, false);
  });

  it("signs up and then logs in", async () => {
    const s = server((path) => (path.endsWith("signup") ? new Response("{}", { status: 201 }) : tokens(1)));
    const session = new Session({ fetch: s.impl, storage: memoryStorage() });
    await session.signUp("a@example.com", "a long passphrase");
    assert.deepEqual(s.calls.map((c) => c.path), ["/v1/auth/signup", "/v1/auth/login"]);
    assert.equal(session.signedIn, true);
  });

  it("refreshes shortly before the access token expires", async () => {
    let clock = 0;
    let n = 0;
    const s = server((path) => (path.endsWith("refresh") ? tokens(++n + 1) : tokens(1)));
    const session = new Session({ fetch: s.impl, storage: memoryStorage(), now: () => clock });
    await session.logIn("a@example.com", "pw");
    clock = 800_000; // 100 s left: still fine
    assert.equal(await session.accessToken(), "a1");
    clock = 880_000; // 20 s left: inside the 30 s skew
    assert.equal(await session.accessToken(), "a2");
    assert.equal(s.calls.at(-1)?.body["refresh_token"], "r1");
  });

  it("shares one refresh between simultaneous callers", async () => {
    let clock = 0;
    let refreshes = 0;
    const s = server(async (path) => {
      if (path.endsWith("refresh")) {
        refreshes += 1;
        await new Promise((r) => setTimeout(r, 10));
        return tokens(2);
      }
      return tokens(1);
    });
    const session = new Session({ fetch: s.impl, storage: memoryStorage(), now: () => clock });
    await session.logIn("a@example.com", "pw");
    clock = 899_000;
    const all = await Promise.all([session.accessToken(), session.accessToken(), session.accessToken()]);
    assert.deepEqual(all, ["a2", "a2", "a2"]);
    assert.equal(refreshes, 1);
  });

  it("signs out when the refresh token is refused, and says so", async () => {
    let clock = 0;
    const s = server((path) => (path.endsWith("refresh") ? problem(401, "unauthenticated") : tokens(1)));
    const storage = memoryStorage();
    const session = new Session({ fetch: s.impl, storage, now: () => clock });
    let changes = 0;
    session.subscribe(() => (changes += 1));
    await session.logIn("a@example.com", "pw");
    clock = 900_000;
    assert.equal(await session.accessToken(), undefined);
    assert.equal(session.signedIn, false);
    assert.equal(storage.data.size, 0);
    assert.equal(changes, 2, "once for login, once for sign-out");
  });

  it("does not sign out on a network failure while refreshing", async () => {
    let clock = 0;
    let down = false;
    const impl: typeof fetch = async (input) => {
      if (down && String(input).endsWith("refresh")) throw new TypeError("fetch failed");
      return tokens(1);
    };
    const session = new Session({ fetch: impl, storage: memoryStorage(), now: () => clock });
    await session.logIn("a@example.com", "pw");
    clock = 900_000;
    down = true;
    await session.accessToken();
    assert.equal(session.signedIn, true);
  });

  it("restores a session after a reload from the stored refresh token", async () => {
    const storage = memoryStorage();
    storage.setItem("falak.refresh", "r9");
    const s = server(() => tokens(5));
    const session = new Session({ fetch: s.impl, storage });
    assert.equal(session.signedIn, true);
    assert.equal(await session.accessToken(), "a5");
    assert.equal(s.calls[0]?.body["refresh_token"], "r9");
  });

  it("logs out locally first and tells the server", async () => {
    const storage = memoryStorage();
    const s = server((path) => (path.endsWith("logout") ? new Response(null, { status: 204 }) : tokens(1)));
    const session = new Session({ fetch: s.impl, storage });
    await session.logIn("a@example.com", "pw");
    await session.logOut();
    assert.equal(session.signedIn, false);
    assert.equal(storage.data.size, 0);
    assert.equal(s.calls.at(-1)?.path, "/v1/auth/logout");
    assert.equal(s.calls.at(-1)?.body["refresh_token"], "r1");
  });

  it("is signed out locally even if the server cannot be reached", async () => {
    let down = false;
    const impl: typeof fetch = async () => {
      if (down) throw new TypeError("fetch failed");
      return tokens(1);
    };
    const session = new Session({ fetch: impl, storage: memoryStorage() });
    await session.logIn("a@example.com", "pw");
    down = true;
    await session.logOut();
    assert.equal(session.signedIn, false);
  });
});
