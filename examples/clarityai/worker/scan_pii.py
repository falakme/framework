#!/usr/bin/env python3
"""ClarityAI NER job: find personal data in unstructured text.

It reports each entity with its kind, span and original text under `pii_entities`.
Office never stores that original text in the job result: on completion it replaces each
`original` with a stable pseudonym token and keeps the token-to-original mapping in an
encrypted, tenant-scoped table.

A real deployment can swap the patterns below for a model; the contract stays the same.
"""
import json
import re
import sys

PATTERNS = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("PHONE", re.compile(r"\+?\d[\d ()-]{8,}\d")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("PERSON", re.compile(r"\b(?:Mr|Mrs|Ms|Dr)\.? [A-Z][a-z]+(?: [A-Z][a-z]+)?")),
]

job = json.load(sys.stdin)
text = job.get("content", "")
found = []
for kind, pattern in PATTERNS:
    for m in pattern.finditer(text):
        found.append({"kind": kind, "start": m.start(), "end": m.end(), "original": m.group(0)})
found.sort(key=lambda e: (e["start"], -e["end"]))
print(json.dumps({"document_id": job.get("document_id"), "tenant": job.get("tenant"), "pii_entities": found}))
