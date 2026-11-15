# Quickstart: a running app in ten minutes

You will describe a small app in YAML, run it, sign up, and save a note. You need
**Rust 1.100** (install it with [rustup](https://rustup.rs)) and `curl`. Nothing else: no
database server, no Docker.

## 1. Build the `falak` command

```sh
git clone https://github.com/falakme/framework.git
cd framework
cargo install --path crates/falak-cli --locked
falak --version
```

`cargo install` puts `falak` in `~/.cargo/bin`. If your shell cannot find it, add that
folder to your `PATH`.

## 2. Create an app

```sh
falak init todo
cd todo
```

This writes:

```text
todo/
├── app.yaml              # name, version, which databases it must run on
├── entities/note.yaml    # the data: a note has a title and a body
└── policies/note.yaml    # who may do what: a person owns their own notes
```

Open `entities/note.yaml`:

```yaml
schema_version: 1
entity: note
owner: owner_id
fields:
  title: { type: text, required: true, max_length: 200 }
  body: { type: text, max_length: 20000 }
  owner_id: { type: uuid, required: true, indexed: true }
```

`owner: owner_id` says that field holds the id of the person who owns the note. The
server fills it in; a client cannot choose it.

## 3. Check and run it

```sh
falak check      # reports mistakes with the file, line and column
falak dev        # serves on http://127.0.0.1:8787 and reloads when you edit a file
```

Leave `falak dev` running and open a second terminal.

`falak dev` keeps its files in `.falak/`: `data.db` (the SQLite database) and `keys.json`
(the key that signs login tokens). Neither belongs in Git; `falak init` already ignores
them.

## 4. Sign up and log in

```sh
curl -s -X POST http://127.0.0.1:8787/v1/auth/signup \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a long passphrase here"}'

curl -s -X POST http://127.0.0.1:8787/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a long passphrase here"}'
```

The login reply holds an `access_token` (valid for 15 minutes) and a `refresh_token`.
Passwords need at least 12 characters. Put the access token in a variable:

```sh
TOKEN=<paste the access_token here>
```

## 5. Save and read a note

```sh
curl -s -X POST http://127.0.0.1:8787/v1/notes \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"title":"First note","body":"It works."}'

curl -s http://127.0.0.1:8787/v1/notes -H "authorization: Bearer $TOKEN"
```

Try the same list request with no token: you get `401`. Sign up a second person and list
again with their token: you see none of the first person's notes. That separation comes
from `policies/note.yaml`, and it is on by default: an entity with no policy allows
nothing.

## 6. Change the app

Add a field to `entities/note.yaml` while `falak dev` runs:

```yaml
  pinned: { type: bool, default: false }
```

The server reloads. The API at `/openapi.json` now describes `pinned`.

> **Known limit:** a change to an existing entity adds no column to the existing table
> yet (migrations arrive in Phase 3). While you are experimenting, delete
> `.falak/data.db` and restart to start with an empty database. `falak dev` warns you when
> this applies.

## 7. Use it from TypeScript

```sh
falak sync . --out web/src/falak.generated.ts
```

This writes a typed client for your app. It uses the `@falak/sdk` package from this
repository's `packages/sdk`:

```ts
import { createClient } from "./falak.generated.ts";

const api = createClient({ baseUrl: "http://127.0.0.1:8787", token });
const note = await api.notes.create({ title: "From TypeScript" });
await api.notes.update(note.id, { body: "Edited" }, { ifMatch: note.version });
for await (const n of api.notes.all({ sort: ["-created_at"] })) console.log(n.title);
```

Writes carry an idempotency key automatically, so a retry after a dropped connection
cannot create a second note. `ifMatch` makes an update fail with `412` if someone else
changed the note first. A complete example is in
[`examples/notebook/web/src/usage.ts`](../examples/notebook/web/src/usage.ts).

## Other commands

| Command | What it does |
| :-- | :-- |
| `falak check [dir]` | Validate the app. |
| `falak build [dir]` | Compile; write `falak.lock` and `.falak/ir.json`. |
| `falak openapi [dir]` | Write `.falak/openapi.json`. |
| `falak sync [dir] --out <file>` | Write the TypeScript client. |
| `falak serve [dir]` | Serve without watching for changes. |
| `falak doctor [dir]` | Check the app, the port and the output folder. |

## Where next

* [`examples/notebook`](../examples/notebook): a larger app with two entities, a relation,
  roles and commands, which the smoke test `scripts/smoke/notebook.sh` exercises.
* [`specifications/API_SPECIFICATION.md`](../specifications/API_SPECIFICATION.md): filters,
  pagination, errors, ETags and idempotency.
* [`specifications/AUTHORIZATION_SPECIFICATION.md`](../specifications/AUTHORIZATION_SPECIFICATION.md):
  exactly what a policy means.
* [`ARCHITECTURE.md`](../ARCHITECTURE.md): the whole design.

## If something goes wrong

* `falak doctor` checks the usual causes.
* `cannot listen on 127.0.0.1:8787`: another program uses the port. Pass `--port 9000`.
* A `401` on every request: the access token lasts 15 minutes. Log in again, or send the
  `refresh_token` to `POST /v1/auth/refresh`.
* The server only listens on `127.0.0.1`, so other machines cannot reach it. Put a
  reverse proxy with TLS in front of it for real use.
