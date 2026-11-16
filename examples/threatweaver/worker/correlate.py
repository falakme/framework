#!/usr/bin/env python3
"""ThreatWeaver correlation job: group indicators that belong together.

Two indicators are linked when they share a network (the same /24 for IPv4) or a registered
domain. The output is a list of clusters, each with the ids it joins.
"""
import collections
import json
import sys


def key(indicator):
    kind, value = indicator.get("kind"), str(indicator.get("value", "")).strip().lower()
    if kind == "ip" and value.count(".") == 3:
        return "net:" + ".".join(value.split(".")[:3]) + ".0/24"
    if kind == "domain":
        return "domain:" + ".".join(value.split(".")[-2:])
    return None


job = json.load(sys.stdin)
groups = collections.defaultdict(list)
for i in job.get("indicators") or []:
    k = key(i)
    if k:
        groups[k].append(i.get("id"))
clusters = [{"link": k, "ids": ids} for k, ids in sorted(groups.items()) if len(ids) > 1]
print(json.dumps({"clusters": clusters, "indicators": len(job.get("indicators") or [])}))
