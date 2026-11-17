#!/usr/bin/env python3
"""Publish the workspace crates to crates.io: idempotent, in dependency order, rate-limit aware.

    scripts/release/publish.py [--dry-run] [--max-wait-minutes N] [--only NAME ...]

For each publishable crate, in dependency order:
  * if this exact version is already in the crates.io index, skip it;
  * otherwise `cargo publish -p NAME --locked` (cargo waits for the index to show the
    crate before returning, so the next crate can depend on it);
  * on HTTP 429 (crates.io rate limit) wait until the time named in the message, then try
    again, for as long as the total budget (--max-wait-minutes, default 290) allows;
  * on any other failure stop at once with the crate named. Nothing is retried blindly.

Re-running after a failure or a timeout is safe: finished crates are skipped.
Crates with `publish = false` are skipped. A publishable crate that depends on one that
is not publishable is an error. The token is read by cargo from CARGO_REGISTRY_TOKEN and
is never passed on a command line or printed.

--dry-run prints the plan and which versions are already on crates.io, and publishes
nothing (it does not need a token).
"""

import argparse
import datetime
import email.utils
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

USER_AGENT = "falak-release-script (https://github.com/falakme/framework)"
RETRY_RE = re.compile(r"try again after (.+?) and see", re.I)


def metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def publishable(pkg):
    # `publish = false` is `[]`; `publish = ["other-registry"]` is not crates.io either.
    return pkg["publish"] is None or "crates-io" in pkg["publish"]


def plan(meta):
    """Return the publishable packages in dependency order; raise on a bad graph."""
    pkgs = {p["name"]: p for p in meta["packages"]}
    for p in pkgs.values():
        if not publishable(p):
            continue
        for d in p["dependencies"]:
            dep = pkgs.get(d["name"])
            if dep is not None and d["kind"] != "dev" and not publishable(dep):
                raise SystemExit(f"{p['name']} depends on {dep['name']}, which has publish = false")
        for field in ("description", "license", "repository"):
            if not (p.get(field) or (field == "license" and p.get("license_file"))):
                raise SystemExit(f"{p['name']} has no {field}; crates.io requires it")
    names = [n for n, p in pkgs.items() if publishable(p)]

    def edges(with_dev):
        return {
            n: {
                d["name"] for d in pkgs[n]["dependencies"]
                if d["name"] in names and d["name"] != n and (with_dev or d["kind"] != "dev")
            }
            for n in names
        }

    for with_dev in (True, False):  # a dev-dependency cycle is allowed; cargo ignores it when building
        deps = edges(with_dev)
        order, left = [], dict(deps)
        while left:
            ready = sorted(n for n, d in left.items() if d <= set(order))
            if not ready:
                break
            order.extend(ready)
            for n in ready:
                del left[n]
        if not left:
            return [pkgs[n] for n in order]
    raise SystemExit("dependency cycle between publishable crates: " + ", ".join(sorted(left)))


def index_path(name):
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def on_crates_io(name, version):
    """True if name@version is in the crates.io sparse index (yanked counts: it cannot be reused)."""
    url = f"https://index.crates.io/{index_path(name)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read().decode()
            return any(json.loads(line).get("vers") == version for line in body.splitlines() if line.strip())
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return False
            err = e
        except (urllib.error.URLError, TimeoutError) as e:
            err = e
        time.sleep(2 ** attempt)
    raise SystemExit(f"cannot read the crates.io index for {name}: {err}")


def retry_after(message, now=None):
    """Seconds to wait named by a crates.io 429 message, or None if it names none."""
    m = RETRY_RE.search(message)
    if not m:
        return None
    try:
        when = email.utils.parsedate_to_datetime(m.group(1).strip())
    except (TypeError, ValueError):
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0.0, (when - now).total_seconds())


def publish(name, deadline):
    attempt = 0
    while True:
        attempt += 1
        print(f"==> cargo publish -p {name} (attempt {attempt})", flush=True)
        r = subprocess.run(
            ["cargo", "publish", "-p", name, "--locked"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        print(r.stdout, end="", flush=True)
        if r.returncode == 0:
            return "published"
        if re.search(r"already exists on crates\.io", r.stdout):
            return "already there"  # published meanwhile (or the index lagged our check)
        if "429" in r.stdout and "Too Many Requests" in r.stdout:
            wait = retry_after(r.stdout)
            wait = (wait if wait is not None else 600) + 15  # a margin past the stated time
            if time.monotonic() + wait > deadline:
                raise SystemExit(f"{name}: rate limited by crates.io and the time budget is spent; run again later")
            print(f"crates.io rate limit: waiting {int(wait)}s", flush=True)
            time.sleep(wait)
            continue
        raise SystemExit(f"{name}: cargo publish failed (not a rate limit); stopping")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--max-wait-minutes", type=float, default=290)
    ap.add_argument("--only", nargs="*", help="publish just these crates (still in order)")
    args = ap.parse_args()

    order = plan(metadata())
    if args.only:
        order = [p for p in order if p["name"] in args.only]
    print("order: " + ", ".join(p["name"] for p in order))
    deadline = time.monotonic() + args.max_wait_minutes * 60
    summary = []
    for p in order:
        name, version = p["name"], p["version"]
        if on_crates_io(name, version):
            print(f"{name} {version}: already on crates.io, skipped", flush=True)
            summary.append((name, "skipped (exists)"))
        elif args.dry_run:
            print(f"{name} {version}: would publish", flush=True)
            summary.append((name, "would publish"))
        else:
            summary.append((name, publish(name, deadline)))
    print("\nsummary")
    for name, what in summary:
        print(f"  {name}: {what}")


if __name__ == "__main__":
    sys.exit(main())
