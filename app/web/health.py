"""The health status APEX Pingmora reads: ``GET /healthz/pingmora`` (suite-health/1).

``/healthz`` stays the cheap liveness probe. This one runs the checks (database, disk, and the
app's own hard dependencies), each with a 2 s timeout and 5 s in total, at most once every 10 s.

Without credentials it answers the public summary (format, key, status, time). With
``Authorization: Bearer <token>`` it adds version, uptime and the checks, when the token is either
an API token with the ``read`` scope (verified by the caller's ``verify_token``) or the deployment's
``PINGMORA_HEALTH_TOKEN`` (at least 32 characters, compared in constant time). A missing or wrong
token is not an error: the summary is returned. The token is never logged.

Stdlib only, framework-neutral: ``Health.respond(authorization)`` returns ``(status, body)``.
"""

from __future__ import annotations

import hmac
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Callable

FORMAT = "suite-health/1"
CHECK_TIMEOUT = 2.0      # seconds per check
TOTAL_TIMEOUT = 5.0      # seconds for all checks together
CACHE_SECONDS = 10.0     # a result is reused this long, so frequent probes cannot load the app
TOKEN_ENV = "PINGMORA_HEALTH_TOKEN"
TOKEN_MIN = 32
HEADERS = {"Cache-Control": "no-store"}

_RANK = {"up": 0, "degraded": 1, "down": 2}

# A check returns {"status": "up"|"degraded"|"down", "message"?: str} (or None for up); raising,
# or not answering within CHECK_TIMEOUT, makes it "down".
Check = Callable[[], "dict | None"]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def worst(statuses) -> str:
    out = "up"
    for s in statuses:
        if _RANK.get(s, 2) > _RANK[out]:
            out = s if s in _RANK else "down"
    return out


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def disk_check(data_dir) -> Check:
    """Free space on the filesystem holding DATA_DIR: degraded below 10 % or 1 GB, down below 2 % or 200 MB."""
    def run():
        u = shutil.disk_usage(str(data_dir))
        pct = (u.free / u.total * 100) if u.total else 0.0
        msg = f"DATA_DIR {pct:.0f}% free ({_size(u.free)})"
        if pct < 2 or u.free < 200 * 1024 ** 2:
            return {"status": "down", "message": msg}
        if pct < 10 or u.free < 1024 ** 3:
            return {"status": "degraded", "message": msg}
        return {"status": "up", "message": msg}
    return run


def _run_checks(checks: dict[str, Check]) -> dict[str, dict]:
    results: dict[str, dict] = {}
    threads = []

    def one(name: str, fn: Check) -> None:
        t0 = time.perf_counter()
        try:
            r = dict(fn() or {"status": "up"})
            if r.get("status") not in _RANK:
                r["status"] = "down"
        except Exception as e:  # noqa: BLE001 - a failing check is a result, not an error
            r = {"status": "down", "message": type(e).__name__}
        r.setdefault("latencyMs", round((time.perf_counter() - t0) * 1000, 1))
        results[name] = {k: v for k, v in r.items() if k in ("status", "latencyMs", "message")}

    for name, fn in checks.items():
        t = threading.Thread(target=one, args=(name, fn), name=f"health-{name}", daemon=True)
        t.start()
        threads.append((name, t))
    deadline = time.monotonic() + TOTAL_TIMEOUT
    started = time.monotonic()
    for name, t in threads:
        t.join(max(0.0, min(started + CHECK_TIMEOUT, deadline) - time.monotonic()))
    out = {}
    for name, _t in threads:
        out[name] = results.get(name) or {"status": "down", "message": f"no answer within {CHECK_TIMEOUT:.0f} s"}
    return out


class Health:
    def __init__(self, key: str, version: str | Callable[[], str], checks: dict[str, Check],
                 verify_token: Callable[[str], bool] | None = None, started: float | None = None):
        self.key = key
        self._version = version
        self.checks = checks
        self.verify_token = verify_token      # an app API token with scope read -> True
        self.started = started if started is not None else time.time()
        self._lock = threading.Lock()
        self._cached: tuple[float, dict] | None = None

    @property
    def version(self) -> str:
        return self._version() if callable(self._version) else self._version

    def evaluate(self) -> dict[str, dict]:
        """The checks, from the cache when the last run is under CACHE_SECONDS old."""
        with self._lock:
            if self._cached and time.monotonic() - self._cached[0] < CACHE_SECONDS:
                return self._cached[1]
            res = _run_checks(self.checks)
            self._cached = (time.monotonic(), res)
            return res

    def authorized(self, authorization: str | None, verify_token: Callable[[str], bool] | None = None) -> bool:
        scheme, _, value = (authorization or "").partition(" ")
        value = value.strip()
        if scheme.lower() != "bearer" or not value or len(value) > 512:
            return False
        expected = os.environ.get(TOKEN_ENV, "")
        if len(expected) >= TOKEN_MIN and hmac.compare_digest(value.encode(), expected.encode()):
            return True
        verify = verify_token or self.verify_token
        if verify is not None:
            try:
                return bool(verify(value))
            except Exception:  # noqa: BLE001 - a wrong token only means the summary
                return False
        return False

    def respond(self, authorization: str | None = None,
                verify_token: Callable[[str], bool] | None = None) -> tuple[int, dict]:
        checks = self.evaluate()
        status = worst(c["status"] for c in checks.values())
        body = {"format": FORMAT, "key": self.key, "status": status, "time": now_iso()}
        if self.authorized(authorization, verify_token):
            body["version"] = self.version
            body["uptimeSeconds"] = int(time.time() - self.started)
            body["checks"] = checks
        return (503 if status == "down" else 200), body
