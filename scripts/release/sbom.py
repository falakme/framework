#!/usr/bin/env python3
"""A CycloneDX 1.5 software bill of materials for the Rust programs, from Cargo.lock.

    scripts/release/sbom.py [Cargo.lock] > falak.cdx.json

Every crate in the lock file is listed with its version, its package URL and (for crates
from crates.io) the SHA-256 that Cargo checks it against. Workspace crates are listed
without a hash. This describes what is built into the programs (`falak`, `falak-office`,
`falak-studio`), not the JavaScript packages, which are published on their own.
"""

import datetime
import json
import sys
import tomllib


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "Cargo.lock"
    with open(path, "rb") as f:
        lock = tomllib.load(f)
    version = "0.0.0"
    components = []
    for p in sorted(lock.get("package", []), key=lambda p: (p["name"], p["version"])):
        c = {
            "type": "library",
            "bom-ref": f"pkg:cargo/{p['name']}@{p['version']}",
            "name": p["name"],
            "version": p["version"],
            "purl": f"pkg:cargo/{p['name']}@{p['version']}",
        }
        source = p.get("source")
        if source is None:
            c["scope"] = "required"
            c["properties"] = [{"name": "falak:workspace", "value": "true"}]
        elif source.startswith("registry+"):
            if "checksum" in p:
                c["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
            c["externalReferences"] = [{"type": "distribution", "url": f"https://crates.io/crates/{p['name']}/{p['version']}"}]
        else:
            c["properties"] = [{"name": "cargo:source", "value": source}]
        components.append(c)
    deps = []
    index = {(p["name"], p["version"]): f"pkg:cargo/{p['name']}@{p['version']}" for p in lock.get("package", [])}
    by_name = {}
    for (n, v), ref in index.items():
        by_name.setdefault(n, []).append((v, ref))
    for p in lock.get("package", []):
        refs = []
        for d in p.get("dependencies", []):
            parts = d.split(" ")
            name = parts[0]
            candidates = by_name.get(name, [])
            if len(parts) > 1:
                match = [r for v, r in candidates if v == parts[1]]
            else:
                match = [r for _, r in candidates]
            refs += match
        deps.append({"ref": index[(p["name"], p["version"])], "dependsOn": sorted(set(refs))})
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "falak scripts/release/sbom.py", "version": version}]},
            "component": {"type": "application", "name": "falak", "bom-ref": "falak"},
        },
        "components": components,
        "dependencies": deps,
    }
    json.dump(bom, sys.stdout, indent=2)
    print()


main()
