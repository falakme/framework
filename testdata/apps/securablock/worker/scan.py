#!/usr/bin/env python3
"""SecuraBlock scan job: look for leaked secrets in a text bundle.

Reads the job payload (JSON) on standard input and prints the result as the last line of
standard output. `deep_seconds` simulates a long analysis pass: the job keeps working
(and the worker keeps its lease alive) for that long.
"""
import json
import re
import sys
import time

RULES = [
    ("aws-access-key", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", "high", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("password-assignment", "medium", re.compile(r"(?i)password\s*[=:]\s*['\"][^'\"]{6,}['\"]")),
]


def main():
    job = json.load(sys.stdin)
    findings = []
    for number, line in enumerate(job.get("content", "").splitlines(), start=1):
        for rule, severity, pattern in RULES:
            if pattern.search(line):
                findings.append({"rule": rule, "severity": severity, "line": number})
    deadline = time.time() + int(job.get("deep_seconds") or 0)
    while time.time() < deadline:
        time.sleep(0.5)
    print("scanned", len(findings), "findings", file=sys.stderr)
    print(json.dumps({"scan_id": job.get("scan_id"), "finding_count": len(findings), "findings": findings}))


main()
