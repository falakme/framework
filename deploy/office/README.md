# Deploying Office and Studio

## Install and set up (any machine)

```
curl -fsSL https://raw.githubusercontent.com/falakme/framework/main/scripts/install.sh | sh
falak-office serve
```

`serve` prints a link with a one-time setup code. Open it, make the administrator, and use the console to connect apps, add people and turn on sign-in through Clerk, Auth0 or another provider. No terminal needed after the first command.

Prefer the terminal? Skip the browser:

```
OFFICE_PASSWORD='a long password' falak-office setup --email you@example.com --password-env OFFICE_PASSWORD --issuer https://office.example.com
falak-office serve
```

Both ways make the same thing. The setup code exists only while nobody has an account, is printed only on the console, and works once. The public address is saved in `settings.json` in the data directory (`.falak-office` by default, `FALAK_OFFICE_DATA` to change it) and applies at the next start. Sign-in through a provider applies at once. The console is `http://127.0.0.1:8788/` by default; for a server, put https in front of it and give `--host 0.0.0.0` (or `FALAK_OFFICE_HOST`).

One image (`Dockerfile`), one PostgreSQL database, two programs. `docker-compose.yml` runs all three.

**Status.** The Dockerfile and compose file are written but have not been built or deployed from here: the Coolify connection was down, and the image has not been built on this machine. The programs themselves are tested (`scripts/smoke/office.sh` on SQLite and PostgreSQL 16).

## On Coolify

1. New resource, "Docker Compose", source `github.com/falakme/framework`, compose file `deploy/office/docker-compose.yml`.
2. Variables: `OFFICE_DB_PASSWORD` (long, random), `OFFICE_URL` (the https address of `office`, for example `https://office.falak.me`). Optional: `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_AUTO_CREATE` for sign-in through Clerk, Auth0 or another OpenID Connect provider.
3. Domains: `office` on port 8788, `studio` on port 8790. Both over https. Studio also needs `studio.json` next to the compose file (see below), with `"cookie_secure": true`.
4. First administrator, once the stack is up (from the `office` container's terminal):

   ```
   OFFICE_PW='a long password' falak-office user add --email you@example.com --password-env OFFICE_PW --role office_admin
   ```

5. Enroll each app: an administrator makes an enrollment token (`POST /v1/_office/enrollments`), then, with the token in an environment variable so it stays out of the process list and shell history, `FALAK_ENROLL_TOKEN=<token> falak office enroll <app dir> --office https://office.falak.me` (or `--token-env VAR` to name another variable). The `--token <t>` flag still works but shows in `ps`. The CLI refuses to send the token to a plain `http` Office URL unless it is this machine.

## `studio.json`

```json
{
  "office_url": "https://office.falak.me",
  "apps": [{ "name": "notebook", "url": "https://notebook.example.com" }],
  "cookie_secure": true
}
```

## What to back up

* The `office-db` volume (people, apps, memberships, revocations).
* The signing and session keys are in the database (`office_keystore`); `office-data` holds a local copy and `vault-kek.json` (the key-encryption key, unless `FALAK_VAULT_KEK` is set). Keep the KEK apart from database backups: without it the wrapped tenant data keys cannot be opened.
* The `studio-data` volume holds the audit log (`falak-studio audit-verify /data/audit.jsonl`).

## Not in the image

TLS, which Coolify's proxy does.

## More than one Office

Two or more instances can share one database: keys, sessions, revocations and the audit chain are all in it. See `docker-compose.ha.yml` and `docs/operations.md` (high availability, disaster recovery, break-glass, rotation and anchoring, objectives and alerts).
