#!/usr/bin/env python3
"""Tests for publish.py: python3 scripts/release/test_publish.py"""

import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import publish  # noqa: E402

MSG = (
    "the remote server responded with an error (status 429 Too Many Requests): You have "
    "published too many new crates in a short period of time. Please try again after "
    "Mon, 16 Nov 2026 08:11:08 GMT and see https://crates.io/docs/rate-limits for more details."
)


def pkg(name, deps=(), publish_=None, dev=()):
    d = [{"name": n, "kind": None} for n in deps] + [{"name": n, "kind": "dev"} for n in dev]
    return {"name": name, "version": "1.0.0", "publish": publish_, "dependencies": d,
            "description": "x", "license": "MIT", "repository": "r"}


class T(unittest.TestCase):
    def test_retry_after(self):
        now = datetime.datetime(2026, 11, 16, 8, 1, 10, tzinfo=datetime.timezone.utc)
        self.assertEqual(publish.retry_after(MSG, now), 598.0)
        self.assertEqual(publish.retry_after("nothing here"), None)

    def test_order(self):
        m = {"packages": [pkg("c", ["b"]), pkg("b", ["a"]), pkg("a", dev=["c"]), pkg("w", publish_=[])]}
        self.assertEqual([p["name"] for p in publish.plan(m)], ["a", "b", "c"])

    def test_unpublishable_dependency(self):
        m = {"packages": [pkg("a", ["w"]), pkg("w", publish_=[])]}
        with self.assertRaises(SystemExit):
            publish.plan(m)

    def test_index_path(self):
        self.assertEqual(publish.index_path("falak-core"), "fa/la/falak-core")
        self.assertEqual(publish.index_path("abc"), "3/a/abc")


if __name__ == "__main__":
    unittest.main()
