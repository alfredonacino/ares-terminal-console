"""Unit tests of the APEX Pingmora health status (suite-health/1): summary, details, tokens,
503 when a check is down, timeouts and the result cache.

    python -m unittest tests.test_health
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.web import health  # noqa: E402

TOKEN = "p" * 40


class PingmoraHealth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ares-health-test-")

    def make(self, **checks):
        checks.setdefault("disk", health.disk_check(self.tmp))
        return health.Health("ares-test", "1.2.3", checks)

    def test_public_summary_shape(self):
        status, body = self.make(database=lambda: None).respond(None)
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"format", "key", "status", "time"})
        self.assertEqual(body["format"], "suite-health/1")
        self.assertEqual(body["key"], "ares-test")
        self.assertIn(body["status"], ("up", "degraded"))
        self.assertRegex(body["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_details_with_env_token(self):
        with mock.patch.dict(os.environ, {health.TOKEN_ENV: TOKEN}):
            status, body = self.make(database=lambda: None).respond(f"Bearer {TOKEN}")
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], "1.2.3")
        self.assertIsInstance(body["uptimeSeconds"], int)
        self.assertEqual(body["checks"]["database"]["status"], "up")
        self.assertIn("latencyMs", body["checks"]["database"])
        self.assertIn("disk", body["checks"])

    def test_wrong_or_short_token_is_summary(self):
        with mock.patch.dict(os.environ, {health.TOKEN_ENV: TOKEN}):
            h = self.make(database=lambda: None)
            self.assertNotIn("checks", h.respond("Bearer " + "q" * 40)[1])
            self.assertNotIn("checks", h.respond("Basic " + TOKEN)[1])
        with mock.patch.dict(os.environ, {health.TOKEN_ENV: "short"}):
            self.assertNotIn("checks", self.make().respond("Bearer short")[1])

    def test_api_token_verifier(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(health.TOKEN_ENV, None)
            h = self.make()
            self.assertIn("checks", h.respond("Bearer good", lambda v: v == "good")[1])
            self.assertNotIn("checks", h.respond("Bearer bad", lambda v: v == "good")[1])

    def test_down_check_is_503(self):
        def broken():
            raise OSError("database is locked")
        status, body = self.make(database=broken).respond(None)
        self.assertEqual(status, 503)
        self.assertEqual(body["status"], "down")

    def test_degraded_is_200(self):
        status, body = self.make(mail=lambda: {"status": "degraded", "message": "no relay"}).respond(None)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "degraded")

    def test_timeout_is_down(self):
        with mock.patch.object(health, "CHECK_TIMEOUT", 0.2):
            t0 = time.monotonic()
            status, _ = self.make(slow=lambda: time.sleep(2)).respond(None)
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertEqual(status, 503)

    def test_result_is_cached(self):
        calls = []
        h = self.make(database=lambda: calls.append(1))
        h.respond(None)
        h.respond(None)
        self.assertEqual(len(calls), 1)

    def test_disk_thresholds(self):
        gb = 1024 ** 3
        for free, total, want in ((50 * gb, 100 * gb, "up"), (5 * gb, 100 * gb, "degraded"),
                                  (1 * gb, 100 * gb, "down"), (500 * 1024 ** 2, 2 * gb, "degraded")):
            usage = mock.Mock(free=free, total=total)
            with mock.patch.object(health.shutil, "disk_usage", return_value=usage):
                self.assertEqual(health.disk_check(self.tmp)()["status"], want, (free, total))


if __name__ == "__main__":
    unittest.main()
