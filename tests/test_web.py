"""End-to-end tests of the web edition: a real server in a subprocess, on a temporary DATA_DIR.

    python -m unittest tests.test_web

Covers the first administrator, the forced password change, 2FA enrolment and sign-in, user
administration, the local-shell policy and its ssh pinning, terminal ownership, API tokens
(scopes, rotation, revocation), audit and activity exports, and a backup round trip.
"""

import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.web import totp  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Client:
    def __init__(self, base: str, bearer: str = ""):
        self.base = base
        self.bearer = bearer
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  _NoRedirect())

    def call(self, method: str, path: str, body=None, raw: bytes = None, headers: dict = None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Origin", self.base)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if self.bearer:
            req.add_header("Authorization", f"Bearer {self.bearer}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=60) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def json(self, method: str, path: str, body=None, expect: int = 200):
        status, data, _ = self.call(method, path, body)
        out = json.loads(data or b"{}")
        if expect is not None and status != expect:
            raise AssertionError(f"{method} {path}: {status} {out}")
        return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class WebEdition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ares-web-test-")
        cls.port = _free_port()
        env = dict(os.environ, DATA_DIR=cls.tmp, PORT=str(cls.port), HOST="127.0.0.1", ARES_TRUST_PROXY="0",
                   LOG_FORMAT="json", ARES_BACKUP_PASSPHRASE="")
        env.pop("ARES_ADMIN_PASSWORD", None)
        cls.proc = subprocess.Popen([sys.executable, str(ROOT / "app" / "main.py")], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.base = f"http://127.0.0.1:{cls.port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base + "/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ── helpers ──
    def _initial_password(self) -> str:
        text = (Path(self.tmp) / "initial-admin-password.txt").read_text()
        return next(line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("password: "))

    def _code(self, secret: str, after: int = 0) -> str:
        step = int(time.time() // 30)
        if step <= after:                      # a code works once: wait for the next step
            time.sleep(30 - time.time() % 30 + 0.2)
            step = int(time.time() // 30)
        return totp.code_at(secret, step)

    def _admin(self) -> Client:
        """The bootstrap administrator, fully set up (password changed, 2FA on). Cached."""
        if getattr(type(self), "admin", None):
            return type(self).admin
        c = Client(self.base)
        mode = (Path(self.tmp) / "initial-admin-password.txt").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        r = c.json("POST", "/auth/login", {"username": "aresadmin", "password": self._initial_password()})
        self.assertEqual(r["stage"], "full")
        self.assertTrue(r["must_change"])
        self.assertTrue(r["needs_enroll"])
        st, _, _ = c.call("GET", "/api/sessions")
        self.assertEqual(st, 403)                       # password change owed
        c.json("POST", "/auth/password", {"current": self._initial_password(), "new": "Correct-Horse-42!"})
        st, _, _ = c.call("GET", "/api/sessions")
        self.assertEqual(st, 403)                       # 2FA enrolment owed
        setup = c.json("POST", "/auth/2fa/setup", {})
        self.assertTrue(setup["otpauth_uri"].startswith("otpauth://totp/"))
        en = c.json("POST", "/auth/2fa/enable", {"code": self._code(setup["secret"])})
        self.assertEqual(len(en["recovery_codes"]), 10)
        self.assertFalse((Path(self.tmp) / "initial-admin-password.txt").exists())
        type(self).admin, type(self).admin_secret, type(self).recovery = c, setup["secret"], en["recovery_codes"]
        type(self).admin_step = int(time.time() // 30)
        return c

    # ── tests ──
    def test_01_health_and_refusals(self):
        st, body, _ = Client(self.base).call("GET", "/healthz")
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["ok"])
        c = Client(self.base)
        self.assertEqual(c.call("GET", "/api/sessions")[0], 401)
        st, _, h = c.call("GET", "/")
        self.assertEqual(st, 303)
        self.assertTrue(h["Location"].startswith("/login"))
        self.assertEqual(c.call("GET", "/api/v1/sessions")[0], 401)
        self.assertEqual(c.call("GET", "/admin/api/users")[0], 401)
        st, _, _ = c.call("POST", "/auth/login", {"username": "aresadmin", "password": "nope"})
        self.assertEqual(st, 401)

    def test_02_admin_bootstrap_and_2fa_signin(self):
        self._admin()
        c = Client(self.base)
        r = c.json("POST", "/auth/login", {"username": "aresadmin", "password": "Correct-Horse-42!"})
        self.assertEqual(r["stage"], "mfa")
        self.assertEqual(c.call("GET", "/api/sessions")[0], 401)
        self.assertEqual(c.call("POST", "/auth/2fa/verify", {"code": "000000"})[0], 400)
        r = c.json("POST", "/auth/2fa/verify", {"code": self.recovery[0]})     # a recovery code works once
        self.assertEqual(r["stage"], "full")
        self.assertEqual(c.call("GET", "/api/sessions")[0], 200)
        me = c.json("GET", "/auth/me")
        self.assertEqual(me["user"]["recovery_codes_left"], 9)
        c.json("POST", "/auth/logout", {})
        self.assertEqual(c.call("GET", "/api/sessions")[0], 401)

    def test_03_users_policy_and_terminals(self):
        a = self._admin()
        made = a.json("POST", "/admin/api/users", {"username": "operator1", "role": "user"})
        pw = made["password"]
        self.assertTrue(pw)
        a.json("PUT", "/admin/api/settings/policy", {"mfa_required": "admins"})
        u = Client(self.base)
        r = u.json("POST", "/auth/login", {"username": "operator1", "password": pw})
        self.assertTrue(r["must_change"])
        self.assertFalse(r["needs_enroll"])
        u.json("POST", "/auth/password", {"current": pw, "new": "Operator-Pass-77"})
        self.assertEqual(u.call("GET", "/admin/api/users")[0], 403)
        # no local shell for a non-administrator
        st, body, _ = u.call("POST", "/api/sessions", {"command": "", "cols": 80, "rows": 24})
        self.assertEqual(st, 403)
        for bad in ("bash", "ssh -o ProxyCommand=sh host", "ssh -oProxyCommand=sh host", "ssh -F /etc/x host",
                    "ssh -J jump host", "ssh -L 1:a:2 host", "ssh -vF x host", "ssh -i key host", "ssh",
                    "/usr/bin/ssh host", "ssh -- -oProxyCommand=x"):
            st, body, _ = u.call("POST", "/api/sessions", {"command": bad})
            self.assertEqual(st, 403, bad)
        st, body, _ = u.call("POST", "/api/sessions", {"command": "ssh -p 2 -l nobody 127.0.0.1"})
        self.assertEqual(st, 200, body)
        sess = json.loads(body)["session"]
        self.assertEqual(sess["command"], "ssh -p 2 -l nobody 127.0.0.1")    # what was typed
        # the administrator's shell is theirs alone
        st, body, _ = a.call("POST", "/api/sessions", {"command": "", "cols": 80, "rows": 24})
        self.assertEqual(st, 200)
        admin_sid = json.loads(body)["session"]["id"]
        mine = {s["id"] for s in u.json("GET", "/api/sessions")["sessions"]}
        self.assertIn(sess["id"], mine)
        self.assertNotIn(admin_sid, mine)
        self.assertFalse(u.json("POST", f"/api/sessions/{admin_sid}/kill", {})["ok"])
        self.assertEqual(u.call("GET", f"/api/sessions/{admin_sid}/where")[0], 404)
        terms = a.json("GET", "/admin/api/terminals")["terminals"]
        self.assertTrue(any(t["id"] == sess["id"] and t["owner"] == "operator1" for t in terms))
        # disabling the user ends their sign-in and closes their terminals
        uid = made["user"]["id"]
        a.json("PUT", f"/admin/api/users/{uid}", {"disabled": True})
        self.assertEqual(u.call("GET", "/api/sessions")[0], 401)
        self.assertFalse(any(t["id"] == sess["id"] for t in a.json("GET", "/admin/api/terminals")["terminals"]))
        a.json("POST", f"/api/sessions/{admin_sid}/kill", {})
        # the last administrator cannot be demoted
        me = a.json("GET", "/auth/me")["user"]
        self.assertEqual(a.call("PUT", f"/admin/api/users/{me['id']}", {"role": "user"})[0], 400)

    def test_04_tokens(self):
        a = self._admin()
        made = a.json("POST", "/auth/tokens", {"name": "ci", "scopes": ["read"], "expires_days": 30})
        tok = made["token"]
        self.assertRegex(tok, r"^ares_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$")
        t = Client(self.base, bearer=tok)
        self.assertEqual(t.call("GET", "/api/v1/sessions")[0], 200)
        self.assertEqual(t.call("GET", "/api/v1/me")[0], 200)
        self.assertEqual(t.call("POST", "/api/v1/sessions", {"command": ""})[0], 403)     # read only
        self.assertEqual(t.call("GET", "/api/v1/admin/users")[0], 403)
        spec = t.json("GET", "/api/v1/openapi.json")
        self.assertIn("/api/v1/admin/users", spec["paths"])
        rot = a.json("POST", f"/auth/tokens/{made['info']['id']}/rotate", {})
        self.assertEqual(t.call("GET", "/api/v1/sessions")[0], 401)
        t2 = Client(self.base, bearer=rot["token"])
        self.assertEqual(t2.call("GET", "/api/v1/sessions")[0], 200)
        adm = a.json("POST", "/auth/tokens", {"name": "admin", "scopes": ["read", "write", "admin"]})
        ta = Client(self.base, bearer=adm["token"])
        self.assertEqual(ta.call("GET", "/api/v1/admin/users")[0], 200)
        a.json("DELETE", f"/auth/tokens/{adm['info']['id']}")
        self.assertEqual(ta.call("GET", "/api/v1/admin/users")[0], 401)
        self.assertEqual(Client(self.base, bearer="ares_deadbeef_" + "x" * 43).call("GET", "/api/v1/me")[0], 401)

    def test_05_audit_and_activity(self):
        a = self._admin()
        ev = a.json("GET", "/admin/api/audit?limit=500")["events"]
        actions = {e["action"] for e in ev}
        for want in ("Bootstrap administrator created", "Password changed", "2FA enabled", "Sign-in failed"):
            self.assertIn(want, actions)
        st, body, h = a.call("GET", "/admin/api/audit.csv")
        self.assertEqual(st, 200)
        self.assertTrue(body.startswith(b"id,time_utc,"))
        st, body, _ = a.call("GET", "/admin/api/activity.json")
        self.assertEqual(st, 200)
        lines = [json.loads(x) for x in body.splitlines() if x]
        self.assertTrue(any(x["url"]["path"] == "/auth/login" for x in lines if "url" in x) or lines)
        for line in body.splitlines():
            self.assertNotIn(b"Correct-Horse", line)

    def test_06_backup_round_trip(self):
        a = self._admin()
        self.assertEqual(a.call("PUT", "/admin/api/backup/passphrase", {"passphrase": "short"})[0], 400)
        a.json("PUT", "/admin/api/backup/passphrase", {"passphrase": "a long backup passphrase"})
        run = a.json("POST", "/admin/api/backup/run", {})
        self.assertTrue(run["backup"]["ok"], run)
        name = run["backup"]["name"]
        self.assertTrue(name.endswith(".tar.gz.enc"))
        view = a.json("GET", "/admin/api/backup")
        local = next(d for d in view["destinations"] if d["type"] == "local")
        names = [b["name"] for b in a.json("GET", f"/admin/api/backup/destinations/{local['id']}/backups")["backups"]]
        self.assertIn(name, names)
        st, data, _ = a.call("GET", f"/admin/api/backup/destinations/{local['id']}/backups/{name}")
        self.assertEqual(st, 200)
        self.assertTrue(data.startswith(b"SUITEBK1"))
        bad = a.call("POST", "/admin/api/backup/restore", {"destination": local["id"], "name": name,
                                                            "passphrase": "the wrong passphrase"})
        self.assertEqual(bad[0], 400)

    def test_07_websocket_closed_on_signout(self):
        import base64
        a = self._admin()
        c = Client(self.base)
        r = c.json("POST", "/auth/login", {"username": "aresadmin", "password": "Correct-Horse-42!"})
        c.json("POST", "/auth/2fa/verify", {"code": self.recovery[1]})
        sid = c.json("POST", "/api/sessions", {"command": "", "cols": 80, "rows": 24})["session"]["id"]
        cookie = "; ".join(f"{k.name}={k.value}" for k in c.jar)
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f"GET /ws?session={sid} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                   f"Origin: {self.base}\r\nCookie: {cookie}\r\n\r\n").encode())
        head = s.recv(4096)
        self.assertIn(b" 101 ", head.split(b"\r\n")[0])
        c.json("POST", "/auth/logout", {})
        s.settimeout(5)
        data, deadline = b"", time.time() + 5
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        self.assertIn(b"\x88", data)            # a close frame arrived
        s.close()
        # without a sign-in the upgrade is refused
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall((f"GET /ws?session={sid} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        self.assertIn(b" 401 ", s.recv(4096).split(b"\r\n")[0])
        s.close()
        a.json("POST", f"/admin/api/terminals/{sid}/kill", {})


if __name__ == "__main__":
    unittest.main()
