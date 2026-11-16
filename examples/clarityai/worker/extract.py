#!/usr/bin/env python3
"""ClarityAI extract job: normalise a document's text and count what is in it."""
import json
import re
import sys

job = json.load(sys.stdin)
text = re.sub(r"[ \t]+", " ", job.get("content", "")).strip()
paragraphs = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
print(json.dumps({
    "document_id": job.get("document_id"),
    "characters": len(text),
    "words": len(text.split()),
    "paragraphs": len(paragraphs),
}))
