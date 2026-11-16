#!/usr/bin/env python3
"""PulseAI summary job: the average score and the words people keep using.

It receives scores and comments with no names and no ids tying them to a person, so
nothing in the result can be traced back to one respondent. Swap the word count for a model
call (through the worker's egress socket) without changing the contract.
"""
import collections
import json
import re
import sys

STOP = set("the a an and or but of to in on at for with is are was were be been it this that i we you they my our your their not no so as by from have has had do does did".split())

job = json.load(sys.stdin)
scores = [int(s) for s in job.get("scores") or []]
words = collections.Counter(
    w
    for c in job.get("comments") or []
    for w in re.findall(r"[a-z']{3,}", str(c).lower())
    if w not in STOP
)
print(json.dumps({
    "pulse_id": job.get("pulse_id"),
    "responses": len(scores),
    "average_score": round(sum(scores) / len(scores), 2) if scores else None,
    "themes": [w for w, _ in words.most_common(5)],
}))
