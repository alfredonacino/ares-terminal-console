"""The web layer of ARES Terminal Console, on the standard library's http.server.

    browser ──► app.server.Handler ──► WebApp.handle()     /login /auth/* /saml/* /admin* /api/v1/admin/* …
                                   └─► WebApp.gate()       every terminal route: who is this, may they?

Two modes:

* ``users``: the web edition (Docker, pm2, Kubernetes). Local accounts with TOTP 2FA, Microsoft
  Entra ID / any OpenID Connect provider, SAML 2.0 and LDAP / Active Directory. The first
  administrator is ``aresadmin``.
* ``local``: the desktop app, ``./run.sh`` and ApexBuild. No sign-in at all: every request is the
  built-in local administrator. Backup & Restore, Audit & Activity, Log forwarding and API tokens
  still work; there are no users to manage.

Hot path: a terminal's keystrokes and output travel over its WebSocket, which is authorised once
when it opens. Ordinary requests cost one cached session lookup (re-read from SQLite at most every
few seconds), and audit, activity and log forwarding never block a request.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any, Callable

from . import KEY, __version__, backup, passwords, tokens, totp
from .audit import ACTOR_TOKEN, ACTOR_UA, Activity, Auditor
from .db import Database
from .logs import LOG
from . import logs as logs_mod
from .secretbox import app_key, sealer

STATIC = Path(__file__).resolve().parent.parent / "static" / "gw"
APP_NAME = "ARES Terminal Console"
COOKIE_PLAIN = "ares_tc_session"
COOKIE_SECURE = "__Host-ares_tc_session"
SESSION_TOUCH_EVERY = 30.0
SESSION_CACHE_TTL = 5.0
ACTIVE_WINDOW = 300.0
MFA_ATTEMPTS = 5
MAX_UPLOAD = 8 << 30          # 8 GiB backup upload
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+\\-]{0,127}$")
DEFAULT_ADMIN_USER = "aresadmin"
LOCAL_USER = "local"

DEFAULT_POLICY: dict[str, Any] = {
    "session_idle_minutes": 120,
    "session_max_hours": 12,
    "audit_retention_days": 365,
    "activity_retention_days": 90,
    "local_login": "enabled",          # enabled | admins_only
    "lockout_threshold": 8,
    "lockout_minutes": 15,
    "mfa_required": "all",             # all | admins | optional  (local and LDAP accounts)
    "mfa_for_sso": False,              # also ask Entra / SAML users for a code here
    "local_shell": "admins",           # all | admins | none: who may open a shell on this server
}

DEFAULT_SAML: dict[str, Any] = {
    "enabled": False, "button_label": "Sign in with SAML", "metadata_url": "", "idp_entity_id": "",
    "idp_sso_url": "", "idp_slo_url": "", "idp_certs": [], "sp_entity_id": "",
    "username_claim": "upn", "auto_provision": True, "default_role": "user", "admin_groups": [],
    "allowed_groups": [], "sync_role": True, "allow_idp_initiated": False,
}


def _oidc_defaults() -> dict:
    try:
        from . import oidc
        return dict(oidc.DEFAULTS)
    except Exception:  # noqa: BLE001 - module optional until installed
        return {"enabled": False, "provider": "entra", "button_label": "Sign in with Microsoft",
                "tenant_id": "", "discovery_url": "", "client_id": "", "client_secret_enc": "",
                "scopes": "openid profile email", "username_claim": "preferred_username",
                "groups_claim": "groups", "auto_provision": True, "default_role": "user",
                "admin_groups": [], "allowed_groups": [], "sync_role": True}


def _ldap_defaults() -> dict:
    try:
        from . import ldapauth
        return dict(ldapauth.DEFAULTS)
    except Exception:  # noqa: BLE001
        return {"enabled": False, "server_url": "", "start_tls": False, "verify_tls": True, "ca_pem": "",
                "bind_dn": "", "bind_password_enc": "", "base_dn": "", "user_filter": "",
                "username_attr": "sAMAccountName", "email_attr": "mail", "name_attr": "displayName",
                "group_attr": "memberOf", "auto_provision": True, "default_role": "user",
                "admin_groups": [], "allowed_groups": [], "sync_role": True, "timeout": 10}


# ─── small HTTP plumbing ─────────────────────────────────────────────────────

class HttpError(Exception):
    def __init__(self, status: int, message: str, code: str = "", headers: dict | None = None):
        super().__init__(message)
        self.status, self.message, self.code, self.headers = status, message, code, headers or {}


_STATUS_CODES = {400: "invalid_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
                 405: "method_not_allowed", 409: "conflict", 413: "too_large", 429: "rate_limited",
                 500: "internal_error", 502: "bad_gateway", 503: "unavailable"}


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    ctype: str = "application/json; charset=utf-8"
    headers: list = field(default_factory=list)
    file: Path | None = None             # streamed instead of body
    after: Callable[[], None] | None = None


def json_response(obj: Any, status: int = 200) -> Response:
    return Response(status, json.dumps(obj, default=str).encode(), "application/json; charset=utf-8")


def redirect(location: str, status: int = 303) -> Response:
    return Response(status, b"", "text/plain; charset=utf-8", [("Location", location)])


class Request:
    """What a route handler sees. Wraps the BaseHTTPRequestHandler of this request."""

    def __init__(self, handler, web: "WebApp"):
        self.h = handler
        self.web = web
        self.method = handler.command
        split = urllib.parse.urlsplit(handler.path)
        self.path = split.path
        self.raw_query = split.query
        self.query = urllib.parse.parse_qs(split.query)
        self.headers = handler.headers
        self._body: bytes | None = None
        self.actor: dict = {"user_id": None, "username": "", "token_id": ""}
        self.template = self.path
        self.v1 = self.path.startswith("/api/v1/")

    def q(self, name: str, default: str = "") -> str:
        v = self.query.get(name)
        return v[0] if v else default

    @property
    def ip(self) -> str:
        if self.web.trust_proxy:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()[:64]
            real = self.headers.get("X-Real-IP")
            if real:
                return real.strip()[:64]
        return (self.h.client_address or ("",))[0][:64]

    @property
    def ua(self) -> str:
        return (self.headers.get("User-Agent") or "")[:300]

    @property
    def https(self) -> bool:
        return self.web.trust_proxy and (self.headers.get("X-Forwarded-Proto", "").lower() == "https")

    def length(self) -> int:
        try:
            return max(0, int(self.headers.get("Content-Length") or 0))
        except ValueError:
            return 0

    def body(self) -> bytes:
        if self._body is None:
            n = self.length()
            if n > 4 << 20:
                self.drain()
                raise HttpError(413, "The request body is too large.")
            self._body = self.h.rfile.read(n) if n else b""
        return self._body

    def drain(self) -> None:
        n = self.length()
        while n > 0:
            chunk = self.h.rfile.read(min(n, 1 << 16))
            if not chunk:
                break
            n -= len(chunk)
        self._body = b""

    def json(self) -> dict:
        raw = self.body()
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise HttpError(400, "expected a JSON body")
        if not isinstance(data, dict):
            raise HttpError(400, "expected a JSON object")
        return data

    def form(self) -> dict:
        ctype = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" not in ctype:
            raise HttpError(400, "expected a form post")
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.body().decode("utf-8", "replace")).items()}

    def cookie(self, *names: str) -> str:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except CookieError:
            return ""
        for n in names:
            m = jar.get(n)
            if m and m.value:
                return m.value
        return ""

    def same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        host = (self.headers.get("Host") or "").lower()
        if origin:
            return urllib.parse.urlsplit(origin).netloc.lower() == host
        site = self.headers.get("Sec-Fetch-Site")
        return site in (None, "same-origin", "none")


@dataclass
class Principal:
    """Who is making a request: a signed-in person, a token, or the desktop's local user."""
    user: dict
    via: str                     # session | token | local
    session_id: str = ""
    token_id: str = ""
    scopes: frozenset = frozenset({"read", "write", "admin"})
    stage: str = "full"

    @property
    def uid(self) -> int:
        return int(self.user["id"])

    @property
    def is_admin(self) -> bool:
        return self.user["role"] == "admin" and (self.via != "token" or "admin" in self.scopes)


def _norm_list(v: Any) -> list[str]:
    if isinstance(v, str):
        v = re.split(r"[\s,;]+", v)
    return [str(x).strip() for x in (v or []) if str(x).strip()]


def _safe_next(target: str | None) -> str:
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    return target[:1000]


def _int_in(v: Any, lo: int, hi: int, name: str) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise HttpError(400, f"{name} must be a whole number")
    if not lo <= n <= hi:
        raise HttpError(400, f"{name} must be between {lo} and {hi}")
    return n


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# ─── the application ─────────────────────────────────────────────────────────

class WebApp:
    def __init__(self, data_dir: str | Path, mode: str = "users", *, hooks: dict | None = None,
                 headers: Callable[[], dict] | None = None):
        if mode not in ("users", "local"):
            raise ValueError("mode must be users or local")
        self.mode = mode
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.hooks = hooks or {}
        self.base_headers = headers or (lambda: {})
        self.trust_proxy = mode == "users" and os.environ.get("ARES_TRUST_PROXY", "1") != "0"
        self.started = time.time()

        # A restore staged before the last restart is swapped in before the database opens.
        try:
            backup.apply_pending(self.data_dir, log=lambda m: LOG.app("warn", m, action="backup_restore"))
        except Exception as e:  # noqa: BLE001 - rolled back by apply_pending; keep running
            LOG.app("error", f"applying a staged restore failed: {e!r}", action="backup_restore_failed")

        self.db = Database(self.data_dir / backup.DB_NAME)
        self.app_key = app_key(self.data_dir)
        if mode == "local":
            LOG.environment = os.environ.get("ARES_ENVIRONMENT", "").strip() or "desktop"
        LOG.bind(self.db, self.app_key)
        if mode == "local" or os.environ.get("ARES_LOG_FILE"):
            LOG.set_file(self.data_dir / "logs" / f"{KEY}.jsonl")
        self.audit = Auditor(self.db)
        self.activity = Activity(self.db)
        self.sso_sealer = sealer(self.app_key, "sso")
        self.mfa_sealer = sealer(self.app_key, "mfa")
        self.backup = backup.Service(self.data_dir, app_key_=self.app_key, db=self.db, version=__version__,
                                     on_event=self._backup_event)
        self.uploads = self.data_dir / "backups" / ".uploads"
        backup.hold_server_lock(self.data_dir)

        self._cache: dict[str, tuple[float, dict, dict]] = {}
        self._cache_lock = threading.Lock()
        self._ws: dict[str, set] = {}            # login session id -> closers of its open terminals
        self._ws_lock = threading.Lock()

        restored = backup.take_restore_notice(self.db)
        if restored:
            self.audit.record("system", "Restored from backup", username=restored.get("by", ""),
                              target=f"backup={restored.get('source', '')}", detail=restored)
        if mode == "users":
            self._bootstrap_admin()
        self.local_user = self._local_user() if mode == "local" else None
        self.audit.record("system", "Server started", detail={"version": __version__, "mode": mode,
                                                               "pid": os.getpid()})
        self.routes = self._build_routes()
        threading.Thread(target=self._housekeeping, name="web-housekeeping", daemon=True).start()
        threading.Thread(target=self._scheduler, name="backup-scheduler", daemon=True).start()

    # ── settings ──
    def policy(self) -> dict:
        return {**DEFAULT_POLICY, **(self.db.get_setting("policy", {}) or {})}

    def saml_cfg(self) -> dict:
        return {**DEFAULT_SAML, **(self.db.get_setting("saml", {}) or {})}

    def oidc_cfg(self) -> dict:
        return {**_oidc_defaults(), **(self.db.get_setting("oidc", {}) or {})}

    def ldap_cfg(self) -> dict:
        return {**_ldap_defaults(), **(self.db.get_setting("ldap", {}) or {})}

    def public_url(self) -> str:
        return (os.environ.get("ARES_PUBLIC_URL") or self.db.get_setting("public_url", "") or "").rstrip("/")

    def base_url(self, req: Request) -> str:
        return self.public_url() or f"{'https' if req.https else 'http'}://{req.headers.get('Host', 'localhost')}"

    # ── bootstrap ──
    def _bootstrap_admin(self) -> None:
        if self.db.count_users() > 0:
            return
        username = os.environ.get("ARES_ADMIN_USER", DEFAULT_ADMIN_USER).strip() or DEFAULT_ADMIN_USER
        given = os.environ.get("ARES_ADMIN_PASSWORD", "")
        if given and passwords.policy_error(given, username):
            LOG.app("warn", "ARES_ADMIN_PASSWORD does not meet the password policy; a one-time password "
                            "was generated instead", action="bootstrap_admin")
            given = ""
        password = given or passwords.generate()
        t = time.time()
        self.db.execute(
            "INSERT INTO users (username, display_name, role, auth_source, password_hash, must_change, "
            "created_at, updated_at) VALUES (?, 'Administrator', 'admin', 'local', ?, ?, ?, ?)",
            (username, passwords.hash_password(password), 0 if given else 1, t, t))
        if not given:
            p = self.data_dir / "initial-admin-password.txt"
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(f"username: {username}\npassword: {password}\n"
                         "This one-time password must be changed at the first sign-in, and two-factor "
                         "authentication set up. This file is deleted when that is done.\n")
            LOG.app("warn", f"created the first administrator '{username}'; its one-time password is in "
                            f"{p.name} in the data directory (mode 600)", action="bootstrap_admin")
        self.audit.record("system", "Bootstrap administrator created", username=username,
                          target=f"user={username}")

    def _local_user(self) -> dict:
        u = self.db.one("SELECT * FROM users WHERE builtin = 1 LIMIT 1")
        if u:
            return u
        t = time.time()
        name = LOCAL_USER
        if self.db.user_by_name(name):
            name = f"{LOCAL_USER}-{secrets.token_hex(2)}"
        self.db.execute("INSERT INTO users (username, display_name, role, auth_source, builtin, created_at, "
                        "updated_at) VALUES (?, 'This computer', 'admin', 'local', 1, ?, ?)", (name, t, t))
        return self.db.one("SELECT * FROM users WHERE builtin = 1 LIMIT 1")

    # ── background work ──
    def _housekeeping(self) -> None:
        last_purge = 0.0
        while True:
            try:
                pol = self.policy()
                t = time.time()
                idle = max(5, int(pol["session_idle_minutes"])) * 60.0
                self.db.execute("UPDATE sessions SET ended_at = ?, end_reason = 'expired' "
                                "WHERE ended_at IS NULL AND expires_at <= ?", (t, t))
                self.db.execute("UPDATE sessions SET ended_at = last_seen + ?, end_reason = 'idle timeout' "
                                "WHERE ended_at IS NULL AND last_seen + ? <= ?", (idle, idle, t))
                self.db.execute("DELETE FROM saml_requests WHERE created_at < ?", (t - 600,))
                self.db.execute("DELETE FROM saml_assertions WHERE expires_at < ?", (t,))
                self.db.execute("DELETE FROM oidc_states WHERE created_at < ?", (t - 600,))
                self.db.execute("DELETE FROM login_failures WHERE ts < ?", (t - 86400,))
                self._close_dead_sockets()
                if t - last_purge > 86400:
                    n = self.audit.purge(int(pol["audit_retention_days"]))
                    m = self.activity.purge(int(pol["activity_retention_days"]))
                    if n or m:
                        self.audit.record("system", "Audit retention purge",
                                          detail={"audit_deleted": n, "activity_deleted": m})
                    self._sweep_uploads()
                    last_purge = t
            except Exception as e:  # noqa: BLE001 - housekeeping must never die
                LOG.app("error", f"housekeeping error: {e!r}", action="housekeeping_error")
            time.sleep(60)

    def _scheduler(self) -> None:
        time.sleep(30)
        while True:
            try:
                self.backup.run_if_due()
            except Exception as e:  # noqa: BLE001
                LOG.app("error", f"backup scheduler error: {e!r}", action="backup_scheduler_error")
            time.sleep(60)

    def _backup_event(self, action: str, *, outcome: str = "ok", target: str = "", detail: dict | None = None,
                      actor: dict | None = None) -> None:
        a = actor or {}
        self.audit.record("admin" if a.get("id") else "system", action, user_id=a.get("id"),
                          username=a.get("username", ""), ip=a.get("ip", ""), target=target, outcome=outcome,
                          detail=detail)
        if outcome != "ok":
            LOG.app("error", f"{action}: {(detail or {}).get('error') or (detail or {}).get('errors') or ''}",
                    action=logs_mod.slug(action))

    # ── sessions ──
    def _sid(self, token: str) -> str:
        return hmac.new(self.app_key, token.encode(), hashlib.sha256).hexdigest()

    def _invalidate(self, sid: str | None = None) -> None:
        with self._cache_lock:
            if sid is None:
                self._cache.clear()
            else:
                self._cache.pop(sid, None)

    def current(self, req: Request) -> tuple[dict, dict] | None:
        """(session row, user row) of the browser's cookie, or None. Cached for a few seconds."""
        token = req.cookie(COOKIE_SECURE, COOKIE_PLAIN)
        if not token or len(token) > 200:
            return None
        sid = self._sid(token)
        t = time.time()
        with self._cache_lock:
            hit = self._cache.get(sid)
        if hit and t - hit[0] < SESSION_CACHE_TTL:
            return hit[1], hit[2]
        s = self.db.one("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not s or s["ended_at"] is not None:
            self._invalidate(sid)
            return None
        pol = self.policy()
        if s["expires_at"] <= t or s["last_seen"] + int(pol["session_idle_minutes"]) * 60 <= t:
            self.db.execute("UPDATE sessions SET ended_at = ?, end_reason = ? WHERE id = ?",
                            (t, "expired" if s["expires_at"] <= t else "idle timeout", sid))
            self._invalidate(sid)
            self._close_sockets(sid)
            return None
        u = self.db.user(s["user_id"])
        if not u or u["disabled"]:
            return None
        if t - s["last_seen"] > SESSION_TOUCH_EVERY:
            self.db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (t, sid))
            s["last_seen"] = t
        with self._cache_lock:
            if len(self._cache) > 5000:
                self._cache.clear()
            self._cache[sid] = (t, s, u)
        return s, u

    def _start_session(self, req: Request, resp: Response, user: dict, method: str, stage: str) -> str:
        token = secrets.token_urlsafe(32)
        t = time.time()
        pol = self.policy()
        sid = self._sid(token)
        self.db.execute(
            "INSERT INTO sessions (id, user_id, method, stage, created_at, last_seen, expires_at, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, user["id"], method, stage, t, t, t + int(pol["session_max_hours"]) * 3600, req.ip, req.ua))
        if stage == "full":
            self.db.execute("UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?",
                            (t, req.ip, user["id"]))
        secure = req.https
        name = COOKIE_SECURE if secure else COOKIE_PLAIN
        resp.headers.append(("Set-Cookie", f"{name}={token}; Path=/; Max-Age={int(pol['session_max_hours']) * 3600}; "
                                           f"HttpOnly; SameSite=Lax{'; Secure' if secure else ''}"))
        return sid

    @staticmethod
    def _clear_cookie(resp: Response) -> None:
        resp.headers.append(("Set-Cookie", f"{COOKIE_PLAIN}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"))
        resp.headers.append(("Set-Cookie", f"{COOKIE_SECURE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"))

    def end_sessions(self, user_id: int, reason: str, except_sid: str = "") -> int:
        rows = self.db.all("SELECT id FROM sessions WHERE user_id = ? AND ended_at IS NULL AND id != ?",
                           (user_id, except_sid))
        self.db.execute("UPDATE sessions SET ended_at = ?, end_reason = ? "
                        "WHERE user_id = ? AND ended_at IS NULL AND id != ?",
                        (time.time(), reason, user_id, except_sid))
        self._invalidate()
        for r in rows:
            self._close_sockets(r["id"])
        return len(rows)

    # ── open terminals per login session (closed when the session ends) ──
    def register_socket(self, p: Principal, closer: Callable[[], None]) -> Callable[[], None]:
        key = p.session_id or f"tok:{p.token_id}" or "local"
        with self._ws_lock:
            self._ws.setdefault(key, set()).add(closer)

        def done() -> None:
            with self._ws_lock:
                s = self._ws.get(key)
                if s is not None:
                    s.discard(closer)
                    if not s:
                        self._ws.pop(key, None)
        return done

    def _close_sockets(self, sid: str) -> None:
        with self._ws_lock:
            closers = list(self._ws.pop(sid, ()))
        for c in closers:
            try:
                c()
            except Exception:  # noqa: BLE001
                pass

    def _close_dead_sockets(self) -> None:
        with self._ws_lock:
            keys = [k for k in self._ws if not k.startswith("tok:") and k != "local"]
        if not keys:
            return
        dead = self.db.all("SELECT id FROM sessions WHERE ended_at IS NOT NULL AND id IN (%s)"
                           % ",".join("?" * len(keys)), tuple(keys))
        for r in dead:
            self._close_sockets(r["id"])

    # ── who may do what ──
    def mfa_required_for(self, u: dict) -> bool:
        if self.mode == "local" or u.get("builtin"):
            return False
        pol = self.policy()
        if u["auth_source"] in ("saml", "oidc") and not pol["mfa_for_sso"]:
            return bool(u["totp_enabled"])
        req = pol["mfa_required"]
        return req == "all" or (req == "admins" and u["role"] == "admin") or bool(u["totp_enabled"])

    def needs(self, s: dict | None, u: dict) -> dict:
        must_change = bool(u["must_change"]) and u["auth_source"] == "local"
        stage = (s or {}).get("stage", "full")
        return {"mfa_verify": stage == "mfa",
                "password_change": must_change,
                "mfa_enroll": self.mfa_required_for(u) and not u["totp_enabled"]}

    def may_local_shell(self, p: Principal) -> bool:
        if self.mode == "local":
            return True
        rule = self.policy()["local_shell"]
        return rule == "all" or (rule == "admins" and p.user["role"] == "admin")

    def _set_actor(self, req: Request, user: dict | None, token_id: str = "") -> None:
        req.actor = {"user_id": user["id"] if user else None, "username": user["username"] if user else "",
                     "token_id": token_id}
        ACTOR_TOKEN.set(token_id)
        ACTOR_UA.set(req.ua)

    def _token_principal(self, req: Request, need: str | None) -> Principal:
        ip = req.ip
        ACTOR_UA.set(req.ua)
        try:
            row, owner, _secret = tokens.authenticate(self.db, req.headers.get("Authorization", ""), ip)
        except tokens.TokenError as e:
            req.actor = {"user_id": None, "username": "", "token_id": e.token_id}
            if e.code not in ("missing_token", "rate_limited"):
                tokens.record_failure(self.db, ip)
            if e.code != "missing_token":
                self.audit.record("api", "API token rejected", ip=ip, token_id=e.token_id,
                                  outcome="denied" if e.status == 429 else "fail", status=e.status,
                                  target=f"token={e.token_id}" if e.token_id else "",
                                  detail={"reason": e.code, "path": req.path})
            raise HttpError(e.status, e.message, e.code,
                            {"WWW-Authenticate": 'Bearer realm="api"'} if e.status == 401 else None)
        if owner.get("builtin") and self.mode != "local":
            raise HttpError(401, "The token's owner is not usable here.", "owner_disabled")
        self._set_actor(req, owner, row["id"])
        scopes = tokens.effective_scopes(row, owner)
        if need and need not in scopes:
            tokens.record_failure(self.db, ip)
            self.audit.record("api", "API token lacks scope", user=owner, ip=ip, outcome="denied", status=403,
                              target=f"token={row['id']}",
                              detail={"needed": need, "scopes": sorted(scopes), "path": req.path})
            why = " Its owner is no longer an administrator." if need == "admin" and "admin" in row["scopes"] else ""
            raise HttpError(403, f"This token needs the '{need}' scope.{why}", "insufficient_scope")
        if owner["must_change"] and owner["auth_source"] == "local" and self.mode == "users":
            raise HttpError(403, "The token's owner must change their password first.", "password_change_required")
        return Principal(owner, "token", token_id=row["id"], scopes=frozenset(scopes))

    def require(self, req: Request, *, admin: bool = False, any_scope: bool = False,
                partial: bool = False) -> Principal:
        """The principal for this request, or HttpError. ``partial``: a session still owing 2FA,
        a password change or enrolment may proceed (the account routes)."""
        if req.v1:
            need = None if any_scope else "admin" if admin else ("read" if req.method in ("GET", "HEAD") else "write")
            return self._token_principal(req, need)
        if req.method not in ("GET", "HEAD") and not req.same_origin():
            raise HttpError(403, "cross-origin request refused")
        if self.mode == "local":
            u = self.local_user
            self._set_actor(req, u)
            return Principal(u, "local")
        cur = self.current(req)
        if not cur:
            raise HttpError(401, "Your session has ended. Sign in again.")
        s, u = cur
        self._set_actor(req, u)
        p = Principal(u, "session", session_id=s["id"], stage=s["stage"])
        if s["stage"] == "mfa" and not partial:
            raise HttpError(401, "Enter your two-factor code first.", "mfa_required")
        if not partial:
            n = self.needs(s, u)
            if n["password_change"]:
                raise HttpError(403, "You must change your password first.", "password_change_required")
            if n["mfa_enroll"]:
                raise HttpError(403, "Set up two-factor authentication first.", "mfa_enroll_required")
        if admin and u["role"] != "admin":
            self.audit.record("admin", "Admin access denied", user=u, ip=req.ip, target=req.path, outcome="denied")
            raise HttpError(403, "administrators only")
        return p

    # ── the entry points used by app.server ──
    def client(self, handler) -> tuple[str, str]:
        """(client IP, user agent) of a request, honouring the proxy headers when trusted."""
        r = Request(handler, self)
        return r.ip, r.ua

    def gate(self, handler, *, kind: str = "api") -> Principal | None:
        """Authorise a terminal route (``kind`` api | page | ws). Sends the refusal itself on None."""
        req = Request(handler, self)
        ACTOR_TOKEN.set("")
        try:
            if req.v1:
                need = "read" if req.method in ("GET", "HEAD") else "write"
                p = self._token_principal(req, need)
            else:
                p = self.require(req)
            handler.ares_actor = req.actor
            return p
        except HttpError as e:
            handler.ares_actor = req.actor
            if kind == "page" and e.status in (401, 403) and self.mode == "users":
                nxt = req.path + (("?" + req.raw_query) if req.raw_query else "")
                self._send(handler, req, redirect("/login?" + urllib.parse.urlencode({"next": _safe_next(nxt)})))
            else:
                self._send(handler, req, self._error(req, e))
            return None

    def handle(self, handler) -> bool:
        """Serve a web-layer route. False when the path is not ours (the terminal app serves it)."""
        req = Request(handler, self)
        route, params = self._match(req)
        if route is None:
            if req.path.startswith("/api/v1/") and not self._v1_terminal(req.path):
                self._finish(handler, req, self._error(req, HttpError(
                    404, "No such API endpoint. See GET /api/v1/openapi.json.", "not_found")), time.monotonic())
                return True
            return False
        started = time.monotonic()
        ACTOR_TOKEN.set("")
        ACTOR_UA.set(req.ua)
        req.template = route["template"]
        try:
            out = route["fn"](req, **params)
            resp = out if isinstance(out, Response) else json_response(out)
        except HttpError as e:
            resp = self._error(req, e)
        except Exception as e:  # noqa: BLE001 - never a trace to the client
            LOG.app("error", f"{req.method} {route['template']} failed: {e!r}", action="request_error")
            resp = self._error(req, HttpError(500, "Internal error; it has been logged."))
        self._finish(handler, req, resp, started)
        return True

    @staticmethod
    def _v1_terminal(path: str) -> bool:
        rest = path[len("/api/v1"):]
        return rest.startswith(("/sessions", "/history", "/commands", "/connections", "/servers", "/colors",
                                "/insight/"))

    def _finish(self, handler, req: Request, resp: Response, started: float) -> None:
        self._send(handler, req, resp)
        self.record_activity(req.method, req.template, resp.status, started, req.actor, req.ip, req.ua,
                             v1=req.v1)

    def record_activity(self, method: str, template: str, status: int, started: float, actor: dict | None,
                        ip: str, ua: str, v1: bool = False) -> None:
        if method in ("GET", "HEAD", "OPTIONS") and not v1:
            return
        a = actor or {}
        try:
            self.activity.record(method=method, path=template, status=status,
                                 duration_ms=(time.monotonic() - started) * 1000, user_id=a.get("user_id"),
                                 username=a.get("username", ""), token_id=a.get("token_id", ""), ip=ip,
                                 user_agent=ua)
        except Exception as e:  # noqa: BLE001 - logging must not fail the request
            LOG.app("error", f"activity log write failed: {e!r}", action="activity_error")

    def _error(self, req: Request, e: HttpError) -> Response:
        if req.v1:
            r = json_response({"error": e.code or _STATUS_CODES.get(e.status, "error"), "message": e.message},
                              e.status)
        else:
            body = {"detail": e.message}
            if e.code:
                body["code"] = e.code
            r = json_response(body, e.status)
        r.headers.extend(e.headers.items())
        return r

    def _send(self, handler, req: Request, resp: Response) -> None:
        h = handler
        h.ares_status = resp.status
        try:
            h.send_response(resp.status)
            size = resp.file.stat().st_size if resp.file is not None else len(resp.body)
            h.send_header("Content-Type", resp.ctype)
            h.send_header("Content-Length", str(size))
            base = dict(self.base_headers())
            base["Cache-Control"] = "no-store"
            if req.https:
                base["Strict-Transport-Security"] = "max-age=31536000"
            for k, v in base.items():
                if not any(k.lower() == hk.lower() for hk, _ in resp.headers):
                    h.send_header(k, v)
            for k, v in resp.headers:
                h.send_header(k, v)
            h.end_headers()
            if req.method != "HEAD":
                if resp.file is not None:
                    with open(resp.file, "rb") as f:
                        while chunk := f.read(1 << 20):
                            h.wfile.write(chunk)
                else:
                    h.wfile.write(resp.body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if resp.after:
                try:
                    resp.after()
                except Exception:  # noqa: BLE001
                    pass

    # ── routing table ──
    def _build_routes(self) -> list[dict]:
        R: list[tuple[str, str, Callable, str, str]] = []   # method, template, fn, scope, summary

        def add(method: str, tmpl: str, fn: Callable, scope: str = "", v1: str | None = None) -> None:
            R.append((method, tmpl, fn, scope, v1 if v1 is not None else ""))

        # public / account
        add("GET", "/healthz", self.r_healthz)
        add("GET", "/login", self.r_page_login)
        add("GET", "/account", self.r_page_account)
        add("GET", "/admin", self.r_page_admin)
        add("GET", "/gw/{name}", self.r_static)
        add("GET", "/auth/config", self.r_config)
        add("POST", "/auth/login", self.r_login)
        add("POST", "/auth/2fa/verify", self.r_mfa_verify)
        add("POST", "/auth/logout", self.r_logout)
        add("GET", "/auth/me", self.r_me, "any", "/api/v1/me")
        add("POST", "/auth/password", self.r_password)
        add("POST", "/auth/2fa/setup", self.r_mfa_setup)
        add("POST", "/auth/2fa/enable", self.r_mfa_enable)
        add("POST", "/auth/2fa/disable", self.r_mfa_disable)
        add("POST", "/auth/2fa/recovery", self.r_mfa_recovery)
        add("GET", "/auth/oidc/login", self.r_oidc_login)
        add("GET", "/auth/oidc/callback", self.r_oidc_callback)
        add("GET", "/saml/metadata", self.r_saml_metadata)
        add("GET", "/saml/login", self.r_saml_login)
        add("POST", "/saml/acs", self.r_saml_acs)
        add("GET", "/auth/tokens", self.r_tokens, "read", "/api/v1/tokens")
        add("POST", "/auth/tokens", self.r_token_create)
        add("DELETE", "/auth/tokens/{id}", self.r_token_revoke, "write", "/api/v1/tokens/{id}")
        add("POST", "/auth/tokens/{id}/rotate", self.r_token_rotate, "write", "/api/v1/tokens/{id}/rotate")
        add("GET", "/api/v1/openapi.json", self.r_openapi)
        # admin
        A = "/admin/api"
        for method, tmpl, fn in (
                ("GET", "/summary", self.a_summary),
                ("GET", "/users", self.a_users), ("POST", "/users", self.a_user_create),
                ("PUT", "/users/{id}", self.a_user_update), ("DELETE", "/users/{id}", self.a_user_delete),
                ("POST", "/users/{id}/password", self.a_user_password),
                ("POST", "/users/{id}/signout", self.a_user_signout),
                ("POST", "/users/{id}/2fa/reset", self.a_user_mfa_reset),
                ("GET", "/active", self.a_active), ("GET", "/sessions", self.a_sessions),
                ("GET", "/terminals", self.a_terminals), ("POST", "/terminals/{id}/kill", self.a_terminal_kill),
                ("GET", "/audit", self.a_audit), ("GET", "/activity", self.a_activity),
                ("GET", "/audit.csv", lambda r: self.a_export(r, "audit", "csv")),
                ("GET", "/audit.json", lambda r: self.a_export(r, "audit", "json")),
                ("GET", "/activity.csv", lambda r: self.a_export(r, "activity", "csv")),
                ("GET", "/activity.json", lambda r: self.a_export(r, "activity", "json")),
                ("GET", "/tokens", self.a_tokens), ("DELETE", "/tokens/{id}", self.a_token_revoke),
                ("GET", "/logging", self.a_logging), ("POST", "/logging/destinations", self.a_log_add),
                ("PUT", "/logging/destinations/{id}", self.a_log_update),
                ("DELETE", "/logging/destinations/{id}", self.a_log_delete),
                ("POST", "/logging/destinations/{id}/test", self.a_log_test),
                ("GET", "/settings", self.a_settings), ("PUT", "/settings/policy", self.a_policy),
                ("PUT", "/settings/saml", self.a_saml), ("POST", "/settings/saml/metadata", self.a_saml_metadata),
                ("PUT", "/settings/oidc", self.a_oidc), ("POST", "/settings/oidc/test", self.a_oidc_test),
                ("PUT", "/settings/ldap", self.a_ldap), ("POST", "/settings/ldap/test", self.a_ldap_test),
                ("GET", "/backup", self.a_backup), ("PUT", "/backup/schedule", self.a_backup_schedule),
                ("PUT", "/backup/passphrase", self.a_backup_passphrase),
                ("POST", "/backup/destinations", self.a_bdest_add),
                ("PUT", "/backup/destinations/{id}", self.a_bdest_update),
                ("DELETE", "/backup/destinations/{id}", self.a_bdest_delete),
                ("POST", "/backup/destinations/{id}/test", self.a_bdest_test),
                ("GET", "/backup/destinations/{id}/backups", self.a_backup_list),
                ("GET", "/backup/destinations/{id}/backups/{name}", self.a_backup_download),
                ("POST", "/backup/run", self.a_backup_run), ("POST", "/backup/prune", self.a_backup_prune),
                ("POST", "/backup/upload", self.a_backup_upload), ("POST", "/backup/restore", self.a_backup_restore)):
            add(method, A + tmpl, fn, "admin", "/api/v1/admin" + tmpl)

        out = []
        for method, tmpl, fn, scope, v1 in R:
            for path in [tmpl] + ([v1] if v1 else []):
                rx = "^" + re.sub(r"\\\{(\w+)\\\}", r"(?P<\1>[^/]+)", re.escape(path)) + "$"
                out.append({"method": method, "template": path, "rx": re.compile(rx), "fn": fn,
                            "scope": scope, "doc": (getattr(fn, "__doc__", "") or "").strip()})
        return out

    def _match(self, req: Request) -> tuple[dict | None, dict]:
        method = "GET" if req.method == "HEAD" else req.method
        path_hit = False
        for r in self.routes:
            m = r["rx"].match(req.path)
            if m:
                path_hit = True
                if r["method"] == method:
                    return r, {k: urllib.parse.unquote(v) for k, v in m.groupdict().items()}
        if path_hit:
            return {"template": req.path, "fn": self._method_not_allowed}, {}
        return None, {}

    @staticmethod
    def _method_not_allowed(req: Request) -> Response:
        raise HttpError(405, "Method not allowed.")

    # ─── public routes ───────────────────────────────────────────────────────

    def r_healthz(self, req: Request) -> dict:
        """Liveness and readiness: the database answers. Never depends on backups or forwarding."""
        self.db.one("SELECT 1 AS ok")
        return {"ok": True, "version": __version__, "app": KEY}

    def _page(self, name: str) -> Response:
        p = STATIC / name
        if not p.is_file():
            raise HttpError(404, "not found")
        r = Response(200, p.read_bytes(), "text/html; charset=utf-8")
        base = self.base_headers().get("Content-Security-Policy", "")
        m = re.search(r"frame-ancestors [^;]+", base)
        csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
               "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
               + (m.group(0) if m else "frame-ancestors 'self'"))
        r.headers.append(("Content-Security-Policy", csp))
        return r

    def r_page_login(self, req: Request) -> Response:
        if self.mode == "local":
            return redirect("/")
        return self._page("login.html")

    def r_page_account(self, req: Request) -> Response:
        if self.mode == "local":
            return redirect("/admin#tokens")
        if not self.current(req):
            return redirect("/login?next=/account")
        return self._page("account.html")

    def r_page_admin(self, req: Request) -> Response:
        if self.mode == "users":
            cur = self.current(req)
            if not cur:
                return redirect("/login?next=/admin")
            n = self.needs(cur[0], cur[1])
            if any(n.values()):
                return redirect("/login?next=/admin")
            if cur[1]["role"] != "admin":
                return redirect("/")
        return self._page("admin.html")

    def r_static(self, req: Request, name: str) -> Response:
        if not re.fullmatch(r"[a-z0-9_-]+\.(js|css|svg|png)", name) or not (STATIC / name).is_file():
            raise HttpError(404, "not found")
        ext = name.rsplit(".", 1)[1]
        ctype = {"js": "text/javascript; charset=utf-8", "css": "text/css; charset=utf-8",
                 "svg": "image/svg+xml", "png": "image/png"}[ext]
        r = Response(200, (STATIC / name).read_bytes(), ctype)
        r.headers.append(("Cache-Control", "no-cache"))
        return r

    def _fresh_install(self) -> bool:
        if self.db.count_users() != 1:
            return False
        u = self.db.one("SELECT must_change, last_login_at, auth_source FROM users WHERE builtin = 0 LIMIT 1") or {}
        return u.get("auth_source") == "local" and (bool(u.get("must_change")) or u.get("last_login_at") is None)

    def _oidc_ready(self, c: dict) -> bool:
        return bool(c.get("enabled") and c.get("client_id") and c.get("client_secret_enc")
                    and (c.get("tenant_id") or c.get("discovery_url")))

    def _saml_ready(self, c: dict) -> bool:
        return bool(c["enabled"] and c["idp_sso_url"] and c["idp_certs"])

    def r_config(self, req: Request) -> dict:
        pol, o, s, ldap = self.policy(), self.oidc_cfg(), self.saml_cfg(), self.ldap_cfg()
        return {"version": __version__, "app": APP_NAME, "mode": self.mode, "local_login": pol["local_login"],
                "fresh_install": self.mode == "users" and self._fresh_install(),
                "sso": {"oidc": {"enabled": self._oidc_ready(o), "label": o.get("button_label") or "Sign in with Microsoft",
                                 "provider": o.get("provider", "entra")},
                        "saml": {"enabled": self._saml_ready(s), "label": s.get("button_label") or "Sign in with SAML"},
                        "ldap": {"enabled": bool(ldap.get("enabled") and ldap.get("server_url"))}}}

    def _failures(self, key: str, window: float) -> int:
        row = self.db.one("SELECT COUNT(*) AS n FROM login_failures WHERE key = ? AND ts > ?",
                          (key, time.time() - window))
        return int(row["n"]) if row else 0

    def _fail(self, *keys: str) -> None:
        t = time.time()
        for k in keys:
            self.db.execute("INSERT INTO login_failures (key, ts) VALUES (?, ?)", (k, t))

    def _login_result(self, req: Request, user: dict, method: str, detail: dict | None = None) -> Response:
        """Start the session for a user whose first factor checked out; 2FA owed when required."""
        stage = "mfa" if (self.mfa_required_for(user) and user["totp_enabled"]) else "full"
        n = self.needs({"stage": stage}, user)
        resp = json_response({"ok": True, "stage": stage, "must_change": n["password_change"],
                              "needs_enroll": n["mfa_enroll"]})
        sid = self._start_session(req, resp, user, method, stage)
        self._set_actor(req, user)
        self.audit.record("auth", f"Signed in ({method})" if stage == "full" else f"Password accepted ({method}); 2FA code owed",
                          user=user, ip=req.ip, session_id=sid, detail=detail or {})
        return resp

    def r_login(self, req: Request) -> Response:
        """Sign in with a username and password (local account or LDAP / Active Directory)."""
        if self.mode == "local":
            raise HttpError(400, "This copy has no sign-in.")
        if not req.same_origin():
            raise HttpError(403, "cross-origin request refused")
        data = req.json()
        username = str(data.get("username", "")).strip()[:128]
        password = str(data.get("password", ""))[:256]
        ip = req.ip
        pol = self.policy()
        window = int(pol["lockout_minutes"]) * 60
        limit = int(pol["lockout_threshold"])
        ukey, ikey = f"u:{username.lower()}", f"ip:{ip}"
        if self._failures(ukey, window) >= limit or self._failures(ikey, window) >= limit * 3:
            self.audit.record("auth", "Sign-in blocked (too many failures)", username=username, ip=ip,
                              outcome="denied", target=f"user={username}")
            raise HttpError(429, f"Too many failed sign-ins. Try again in {pol['lockout_minutes']} minutes.")
        user = self.db.user_by_name(username) if username else None
        if user and user.get("builtin"):
            user = None
        ldap = self.ldap_cfg()
        use_ldap = bool(ldap.get("enabled") and ldap.get("server_url")) and (user is None or user["auth_source"] == "ldap")
        reason, method = "", "password"
        if use_ldap and password:
            method = "ldap"
            try:
                from . import ldapauth
                ident = ldapauth.authenticate(ldap, self._open_secret(ldap.get("bind_password_enc", "")),
                                              username, password)
                user = self._external_user(ident, ldap, "ldap")
            except HttpError as e:
                reason = e.message
            except Exception as e:  # noqa: BLE001 - LdapError and friends
                code = getattr(e, "code", "")
                reason = "wrong username or password" if code in ("invalid_credentials", "not_found") else \
                    (str(e) if code == "not_allowed" else "")
                if not reason:
                    LOG.app("error", f"LDAP sign-in failed: {e!r}", action="ldap_error")
                    reason = "the directory could not be reached"
        else:
            ok = passwords.verify_password(password, user["password_hash"] if user else "")
            if not user or not ok:
                reason = "wrong username or password"
            elif user["auth_source"] != "local" or not user["password_hash"]:
                reason = "account signs in with SSO only"
        if not reason and user is not None:
            if user["disabled"]:
                reason = "account disabled"
            elif pol["local_login"] == "admins_only" and user["role"] != "admin" and method == "password":
                reason = "password sign-in is limited to administrators"
        if reason or user is None:
            reason = reason or "wrong username or password"
            self._fail(ukey, ikey)
            self.audit.record("auth", "Sign-in failed", user_id=user["id"] if user else None, username=username,
                              ip=ip, outcome="fail", detail={"reason": reason, "method": method},
                              target=f"user={username}")
            shown = reason if reason in ("account signs in with SSO only", "password sign-in is limited to administrators",
                                         "the directory could not be reached") else \
                "Wrong username or password, or the account is disabled."
            raise HttpError(401, shown)
        self.db.execute("DELETE FROM login_failures WHERE key = ?", (ukey,))
        return self._login_result(req, user, method)

    def r_mfa_verify(self, req: Request) -> dict:
        """Finish signing in with a 6-digit code from the authenticator app, or a recovery code."""
        if not req.same_origin():
            raise HttpError(403, "cross-origin request refused")
        cur = self.current(req)
        if not cur:
            raise HttpError(401, "Your session has ended. Sign in again.")
        s, u = cur
        if s["stage"] != "mfa":
            return {"ok": True, **self._needs_out(s, u)}
        code = str(req.json().get("code", "")).strip()
        ok, how = self._check_code(u, code)
        if not ok:
            self._fail(f"mfa:{s['id']}", f"u:{u['username'].lower()}")
            n = self._failures(f"mfa:{s['id']}", 900)
            self.audit.record("auth", "2FA code rejected", user=u, ip=req.ip, outcome="fail", session_id=s["id"],
                              detail={"attempt": n})
            if n >= MFA_ATTEMPTS:
                self.db.execute("UPDATE sessions SET ended_at = ?, end_reason = '2FA attempts exceeded' WHERE id = ?",
                                (time.time(), s["id"]))
                self._invalidate(s["id"])
                raise HttpError(401, "Too many wrong codes. Sign in again.")
            raise HttpError(400, "That code is not right. Check the time on your phone and try again.")
        self.db.execute("UPDATE sessions SET stage = 'full' WHERE id = ?", (s["id"],))
        self.db.execute("UPDATE users SET last_login_at = ?, last_login_ip = ? WHERE id = ?",
                        (time.time(), req.ip, u["id"]))
        self._invalidate(s["id"])
        self._set_actor(req, u)
        self.audit.record("auth", f"Signed in ({s['method']} + 2FA)", user=u, ip=req.ip, session_id=s["id"],
                          detail={"second_factor": how})
        u = self.db.user(u["id"])
        return {"ok": True, **self._needs_out({"stage": "full"}, u)}

    def _needs_out(self, s: dict, u: dict) -> dict:
        n = self.needs(s, u)
        return {"stage": s.get("stage", "full"), "must_change": n["password_change"], "needs_enroll": n["mfa_enroll"]}

    def _check_code(self, u: dict, code: str) -> tuple[bool, str]:
        if not u["totp_enabled"] or not u["totp_secret_enc"]:
            return False, ""
        if totp.looks_like_recovery(code):
            left = totp.use_recovery(json.loads(u["recovery_codes"] or "[]"), code)
            if left is None:
                return False, ""
            self.db.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (json.dumps(left), u["id"]))
            self.audit.record("auth", "Recovery code used", user=u, detail={"remaining": len(left)})
            return True, "recovery code"
        try:
            secret = self.mfa_sealer.open(u["totp_secret_enc"])
        except Exception:  # noqa: BLE001 - APP_KEY changed under it
            return False, ""
        step = totp.verify(secret, code, int(u["totp_last_step"] or 0))
        if not step:
            return False, ""
        self.db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, u["id"]))
        return True, "authenticator"

    def r_logout(self, req: Request) -> Response:
        resp = json_response({"ok": True})
        self._clear_cookie(resp)
        if self.mode == "local":
            return resp
        cur = self.current(req)
        if cur and req.same_origin():
            s, u = cur
            self._set_actor(req, u)
            self.db.execute("UPDATE sessions SET ended_at = ?, end_reason = 'signed out' WHERE id = ?",
                            (time.time(), s["id"]))
            self._invalidate(s["id"])
            self._close_sockets(s["id"])
            self.audit.record("auth", "Signed out", user=u, ip=req.ip, session_id=s["id"])
        return resp

    def public_user(self, u: dict) -> dict:
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"], "email": u["email"],
                "role": u["role"], "auth_source": u["auth_source"], "must_change": bool(u["must_change"]),
                "disabled": bool(u["disabled"]), "mfa_enabled": bool(u["totp_enabled"]),
                "mfa_required": self.mfa_required_for(u), "recovery_codes_left": len(json.loads(u["recovery_codes"] or "[]")),
                "external": bool(u["external_subject"]), "created_at": u["created_at"],
                "updated_at": u["updated_at"], "last_login_at": u["last_login_at"], "last_login_ip": u["last_login_ip"]}

    def r_me(self, req: Request) -> dict:
        """The signed-in user (or the token's owner), the session or token, and what is still owed."""
        p = self.require(req, any_scope=True, partial=True)
        pol = self.policy()
        if p.via == "session":
            s = self.current(req)[0]
            sess = {"method": s["method"], "stage": s["stage"], "created_at": s["created_at"], "expires_at": s["expires_at"]}
            needs = self.needs(s, p.user)
        else:
            sess = {"method": p.via, "stage": "full"}
            if p.via == "token":
                sess |= {"token_id": p.token_id, "scopes": sorted(p.scopes)}
            needs = {"mfa_verify": False, "password_change": False, "mfa_enroll": False}
        return {"user": self.public_user(p.user), "session": sess, "needs": needs, "mode": self.mode,
                "policy": {"mfa_required": pol["mfa_required"], "local_shell": pol["local_shell"],
                           "may_local_shell": self.may_local_shell(p)},
                "version": __version__}

    def r_password(self, req: Request) -> dict:
        """Change your own password (local accounts)."""
        p = self.require(req, partial=True)
        if p.stage == "mfa":
            raise HttpError(401, "Enter your two-factor code first.", "mfa_required")
        u = p.user
        if u["auth_source"] != "local" or u.get("builtin"):
            raise HttpError(400, "This account signs in through its directory or identity provider; "
                                 "change the password there.")
        data = req.json()
        if not passwords.verify_password(str(data.get("current", "")), u["password_hash"]):
            self.audit.record("auth", "Password change failed", user=u, ip=req.ip, outcome="fail")
            raise HttpError(400, "The current password is wrong.")
        new = str(data.get("new", ""))
        err = passwords.policy_error(new, u["username"])
        if err:
            raise HttpError(400, err)
        if passwords.verify_password(new, u["password_hash"]):
            raise HttpError(400, "Choose a password different from the current one.")
        self.db.execute("UPDATE users SET password_hash = ?, must_change = 0, updated_at = ? WHERE id = ?",
                        (passwords.hash_password(new), time.time(), u["id"]))
        ended = self.end_sessions(u["id"], "password changed", except_sid=p.session_id)
        self._invalidate()
        self.audit.record("auth", "Password changed", user=u, ip=req.ip, detail={"other_sessions_ended": ended})
        self._maybe_drop_initial_password(u["id"])
        return {"ok": True, **self._needs_out({"stage": "full"}, self.db.user(u["id"]))}

    def _maybe_drop_initial_password(self, uid: int) -> None:
        u = self.db.user(uid)
        if u and not u["must_change"] and (u["totp_enabled"] or not self.mfa_required_for(u)):
            (self.data_dir / "initial-admin-password.txt").unlink(missing_ok=True)

    def _account(self, req: Request) -> Principal:
        p = self.require(req, partial=True)
        if p.stage == "mfa":
            raise HttpError(401, "Enter your two-factor code first.", "mfa_required")
        if p.via != "session":
            raise HttpError(400, "Two-factor authentication is managed from a browser session.")
        return p

    def r_mfa_setup(self, req: Request) -> dict:
        """Start (or restart) enrolment: a new secret, shown once as a QR code and as text."""
        p = self._account(req)
        u = p.user
        if u["totp_enabled"]:
            raise HttpError(409, "Two-factor authentication is already on. Turn it off first to enrol a new device.")
        secret = totp.new_secret()
        self.db.execute("UPDATE users SET totp_secret_enc = ?, totp_last_step = 0, updated_at = ? WHERE id = ?",
                        (self.mfa_sealer.seal(secret), time.time(), u["id"]))
        self._invalidate()
        uri = totp.otpauth_uri(secret, u["username"], APP_NAME)
        return {"secret": secret, "otpauth_uri": uri, "qr_svg": totp.qr_svg(uri)}

    def r_mfa_enable(self, req: Request) -> dict:
        """Confirm enrolment with the first code; returns ten one-time recovery codes (shown once)."""
        p = self._account(req)
        u = self.db.user(p.uid)
        if u["totp_enabled"]:
            raise HttpError(409, "Two-factor authentication is already on.")
        if not u["totp_secret_enc"]:
            raise HttpError(400, "Start the set-up first.")
        secret = self.mfa_sealer.open(u["totp_secret_enc"])
        step = totp.verify(secret, str(req.json().get("code", "")))
        if not step:
            self.audit.record("auth", "2FA enrolment code rejected", user=u, ip=req.ip, outcome="fail")
            raise HttpError(400, "That code is not right. Check the time on your phone and try again.")
        codes = totp.new_recovery_codes()
        t = time.time()
        self.db.execute("UPDATE users SET totp_enabled = 1, totp_last_step = ?, recovery_codes = ?, "
                        "mfa_enrolled_at = ?, updated_at = ? WHERE id = ?",
                        (step, json.dumps([totp.hash_recovery(c) for c in codes]), t, t, u["id"]))
        self._invalidate()
        self.audit.record("auth", "2FA enabled", user=u, ip=req.ip)
        self._maybe_drop_initial_password(u["id"])
        return {"ok": True, "recovery_codes": codes, **self._needs_out({"stage": "full"}, self.db.user(u["id"]))}

    def r_mfa_disable(self, req: Request) -> dict:
        """Turn two-factor authentication off (only where the policy does not require it)."""
        p = self._account(req)
        u = self.db.user(p.uid)
        if not u["totp_enabled"]:
            return {"ok": True}
        pol = self.policy()
        required = (u["auth_source"] in ("local", "ldap") and (pol["mfa_required"] == "all" or
                    (pol["mfa_required"] == "admins" and u["role"] == "admin"))) or \
                   (u["auth_source"] in ("saml", "oidc") and pol["mfa_for_sso"])
        if required:
            raise HttpError(403, "Your administrator requires two-factor authentication for this account.")
        data = req.json()
        ok, _ = self._check_code(u, str(data.get("code", "")))
        if not ok:
            raise HttpError(400, "Enter a current code from your authenticator app (or a recovery code).")
        self.db.execute("UPDATE users SET totp_enabled = 0, totp_secret_enc = '', recovery_codes = '[]', "
                        "updated_at = ? WHERE id = ?", (time.time(), u["id"]))
        self._invalidate()
        self.audit.record("auth", "2FA disabled", user=u, ip=req.ip)
        return {"ok": True}

    def r_mfa_recovery(self, req: Request) -> dict:
        """New recovery codes (the old ones stop working). Needs a current code."""
        p = self._account(req)
        u = self.db.user(p.uid)
        if not u["totp_enabled"]:
            raise HttpError(400, "Two-factor authentication is off.")
        ok, _ = self._check_code(u, str(req.json().get("code", "")))
        if not ok:
            raise HttpError(400, "Enter a current code from your authenticator app.")
        codes = totp.new_recovery_codes()
        self.db.execute("UPDATE users SET recovery_codes = ?, updated_at = ? WHERE id = ?",
                        (json.dumps([totp.hash_recovery(c) for c in codes]), time.time(), u["id"]))
        self.audit.record("auth", "2FA recovery codes regenerated", user=u, ip=req.ip)
        return {"recovery_codes": codes}

    # ── external identities (OIDC, SAML, LDAP) ──
    def _open_secret(self, blob: str) -> str:
        try:
            return self.sso_sealer.open(blob) if blob else ""
        except Exception:  # noqa: BLE001
            raise HttpError(500, "A stored SSO secret cannot be decrypted (APP_KEY changed): enter it again.")

    def _external_user(self, ident: Any, cfg: dict, source: str) -> dict:
        """Find, provision or update the account of a verified external identity."""
        username = (getattr(ident, "username", "") or "").strip().lower()[:128]
        if not _USERNAME_RE.fullmatch(username or "-"):
            raise HttpError(403, f"The identity provider's username {username!r} cannot be used here.")
        subject = (getattr(ident, "subject", "") or username)[:300]
        groups = list(getattr(ident, "groups", None) or [])
        try:
            from .ldapauth import group_matches
        except Exception:  # noqa: BLE001
            def group_matches(have: list[str], want: list[str]) -> bool:
                return bool({g.lower() for g in have} & {g.lower() for g in want})
        allowed = _norm_list(cfg.get("allowed_groups"))
        if allowed and not group_matches(groups, allowed):
            raise HttpError(403, f"{username} is not in a group allowed to use {APP_NAME}.")
        admin_groups = _norm_list(cfg.get("admin_groups"))
        is_admin = bool(admin_groups) and group_matches(groups, admin_groups)
        email = (getattr(ident, "email", "") or "")[:200]
        display = (getattr(ident, "display_name", "") or username)[:200]

        user = self.db.one("SELECT * FROM users WHERE auth_source = ? AND external_subject = ? AND external_subject != ''",
                           (source, subject))
        if user is None:
            user = self.db.user_by_name(username)
            if user is not None:
                if user.get("builtin"):
                    raise HttpError(403, f"The name {username} is reserved.")
                if user["auth_source"] != source:
                    raise HttpError(403, f"The account {username} signs in another way; ask an administrator "
                                         f"to switch it to {source.upper()}.")
                if user["external_subject"] and user["external_subject"] != subject:
                    raise HttpError(403, f"The account {username} is linked to a different directory object.")
        t = time.time()
        if user is None:
            if not cfg.get("auto_provision", True):
                raise HttpError(403, f"There is no {APP_NAME} account for {username}; ask an administrator.")
            role = "admin" if is_admin else (cfg.get("default_role") if cfg.get("default_role") in ("admin", "user") else "user")
            self.db.execute("INSERT INTO users (username, display_name, email, role, auth_source, external_subject, "
                            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (username, display, email, role, source, subject, t, t))
            user = self.db.user_by_name(username)
            self.audit.record("admin", f"User provisioned from {source.upper()}", user=user, target=f"user={username}",
                              detail={"role": role})
            return user
        if user["disabled"]:
            raise HttpError(403, f"The account {username} is disabled.")
        role = user["role"]
        if cfg.get("sync_role", True) and admin_groups:
            wanted = "admin" if is_admin else "user"
            if wanted != role and not (role == "admin" and self.db.count_admins(exclude_id=user["id"]) == 0):
                self.audit.record("admin", f"Role synced from {source.upper()} groups", user=user,
                                  target=f"user={username}", detail={"from": role, "to": wanted})
                role = wanted
        self.db.execute("UPDATE users SET display_name = ?, email = ?, role = ?, external_subject = ?, updated_at = ? "
                        "WHERE id = ?", (display or user["display_name"], email or user["email"], role, subject, t,
                                         user["id"]))
        self._invalidate()
        return self.db.user(user["id"])

    def _sso_landing(self, req: Request, user: dict, method: str, target: str, detail: dict) -> Response:
        """A page, not a redirect: the IdP started this navigation, and a page that refreshes to the target
        makes the next request same-site so the Lax cookie is sent."""
        stage = "mfa" if (self.mfa_required_for(user) and user["totp_enabled"]) else "full"
        if stage == "mfa" or self.needs({"stage": stage}, user)["mfa_enroll"]:
            target = "/login?" + urllib.parse.urlencode({"next": target})
        esc = target.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
        resp = Response(200, ("<!doctype html><meta charset=utf-8><title>Signing in…</title>"
                              f'<meta http-equiv="refresh" content="0;url={esc}">'
                              '<body style="background:#0d1117;color:#e6edf3;font-family:system-ui">Signing in…'
                              ).encode(), "text/html; charset=utf-8")
        sid = self._start_session(req, resp, user, method, stage)
        self._set_actor(req, user)
        self.audit.record("auth", f"Signed in ({method})" if stage == "full" else f"SSO accepted ({method}); 2FA code owed",
                          user=user, ip=req.ip, session_id=sid, detail=detail)
        return resp

    def _sso_failed(self, req: Request, what: str, e: Exception) -> Response:
        msg = e.message if isinstance(e, HttpError) else str(e)
        self.audit.record("auth", f"{what} sign-in failed", ip=req.ip, outcome="fail", detail={"reason": msg[:500]})
        return redirect("/login?" + urllib.parse.urlencode({"error": f"Single sign-on failed: {msg}"[:400]}))

    def r_oidc_login(self, req: Request) -> Response:
        if self.mode == "local":
            return redirect("/")
        cfg = self.oidc_cfg()
        if not self._oidc_ready(cfg):
            return redirect("/login?error=" + urllib.parse.quote("Microsoft Entra ID / OpenID Connect sign-in is not configured."))
        from . import oidc
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        verifier, challenge = oidc.new_pkce()
        nxt = _safe_next(req.q("next", "/"))
        try:
            url = oidc.auth_url(cfg, self.base_url(req) + "/auth/oidc/callback", state, nonce, challenge)
        except Exception as e:  # noqa: BLE001 - discovery failed
            return self._sso_failed(req, "OIDC", e)
        self.db.execute("INSERT INTO oidc_states (id, created_at, nonce, verifier, next) VALUES (?, ?, ?, ?, ?)",
                        (state, time.time(), nonce, verifier, nxt))
        return redirect(url)

    def r_oidc_callback(self, req: Request) -> Response:
        from . import oidc
        cfg = self.oidc_cfg()
        try:
            if req.q("error"):
                raise HttpError(400, f"{req.q('error')}: {req.q('error_description')[:300]}")
            state = req.q("state")
            row = self.db.one("SELECT * FROM oidc_states WHERE id = ?", (state,)) if state else None
            if row:
                self.db.execute("DELETE FROM oidc_states WHERE id = ?", (state,))
            if not row or row["created_at"] < time.time() - 600:
                raise HttpError(400, "the sign-in took too long or was started elsewhere; try again")
            if not self._oidc_ready(cfg):
                raise HttpError(400, "OpenID Connect sign-in is disabled")
            tok = oidc.exchange_code(cfg, self._open_secret(cfg["client_secret_enc"]), req.q("code"),
                                     self.base_url(req) + "/auth/oidc/callback", row["verifier"])
            claims = oidc.validate_id_token(cfg, tok.get("id_token", ""), row["nonce"], cfg["client_id"])
            ident = oidc.identity(cfg, claims)
            user = self._external_user(ident, cfg, "oidc")
        except Exception as e:  # noqa: BLE001
            return self._sso_failed(req, "OIDC", e)
        return self._sso_landing(req, user, "oidc", row["next"], {"subject": ident.subject[:100]})

    def _sp_entity(self, req: Request) -> str:
        return self.saml_cfg().get("sp_entity_id") or (self.base_url(req) + "/saml/metadata")

    def r_saml_metadata(self, req: Request) -> Response:
        from . import saml
        return Response(200, saml.sp_metadata(self._sp_entity(req), self.base_url(req) + "/saml/acs").encode(),
                        "application/samlmetadata+xml")

    def r_saml_login(self, req: Request) -> Response:
        from . import saml
        cfg = self.saml_cfg()
        if not self._saml_ready(cfg):
            return redirect("/login?error=" + urllib.parse.quote("SAML single sign-on is not configured."))
        nxt = _safe_next(req.q("next", "/"))
        rid, url = saml.build_authn_request(cfg["idp_sso_url"], self._sp_entity(req), self.base_url(req) + "/saml/acs",
                                            relay_state=nxt)
        self.db.execute("INSERT INTO saml_requests (id, created_at, relay) VALUES (?, ?, ?)", (rid, time.time(), nxt))
        return redirect(url)

    def r_saml_acs(self, req: Request) -> Response:
        from . import saml
        cfg = self.saml_cfg()
        try:
            form = req.form()
            relay = _safe_next(form.get("RelayState") or "/")
            if not cfg["enabled"]:
                raise HttpError(400, "SAML single sign-on is disabled")

            def consume(rid: str) -> bool:
                cur = self.db.execute("DELETE FROM saml_requests WHERE id = ? AND created_at > ?",
                                      (rid, time.time() - saml.REQUEST_TTL))
                return (cur.rowcount or 0) == 1

            def remember(aid: str, expires: float) -> bool:
                cur = self.db.execute("INSERT OR IGNORE INTO saml_assertions (id, expires_at) VALUES (?, ?)",
                                      (aid[:200], expires))
                return (cur.rowcount or 0) == 1

            ident = saml.validate_response(
                str(form.get("SAMLResponse") or ""), idp_entity_id=cfg["idp_entity_id"],
                idp_certs=list(cfg["idp_certs"]), sp_entity_id=self._sp_entity(req),
                acs_url=self.base_url(req) + "/saml/acs", consume_request=consume, remember_assertion=remember,
                allow_idp_initiated=bool(cfg["allow_idp_initiated"]))
            user = self._external_user(self._saml_identity(ident, cfg), cfg, "saml")
        except Exception as e:  # noqa: BLE001
            return self._sso_failed(req, "SAML", e)
        return self._sso_landing(req, user, "saml", relay, {"name_id": str(getattr(ident, "name_id", ""))[:200]})

    @staticmethod
    def _saml_identity(ident: Any, cfg: dict) -> Any:
        """A SAML assertion's attributes as the common identity (Entra URIs and plain names alike)."""
        from . import saml
        if hasattr(saml, "to_identity"):
            return saml.to_identity(ident, cfg.get("username_claim", "upn"))

        def first(*names: str) -> str:
            for n in names:
                if n and (v := ident.first(n)):
                    return v
            return ""
        c = lambda name, *alts: (getattr(saml, name, ""),) + alts  # noqa: E731
        upn = first(*c("CLAIM_NAME", "upn", "userPrincipalName")) or ident.name_id
        email = first(*c("CLAIM_EMAIL", "email", "mail")) or (upn if "@" in upn else "")
        display = first(*c("CLAIM_DISPLAY", "displayName", "name", "cn")) or \
            f"{first(*c('CLAIM_GIVEN', 'givenName'))} {first(*c('CLAIM_SURNAME', 'sn', 'surname'))}".strip() or upn
        claim = cfg.get("username_claim", "upn")
        username = email if claim == "email" else ident.name_id if claim == "nameid" else upn
        groups: list[str] = []
        for n in (getattr(saml, "CLAIM_GROUPS", ""), getattr(saml, "CLAIM_ROLE", ""), "groups", "memberOf", "role"):
            if n:
                groups += ident.values(n)
        from types import SimpleNamespace
        return SimpleNamespace(subject=first(*c("CLAIM_OID")) or ident.name_id, username=username or ident.name_id,
                               email=email, display_name=display, groups=groups, source="saml")

    # ── API tokens ──
    def _token_list(self, where: str = "", params: tuple = ()) -> list[dict]:
        rows = self.db.all("SELECT t.*, u.username FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id "
                           + (f"WHERE {where} " if where else "") + "ORDER BY t.created_at DESC", params)
        return [tokens.public(r) for r in rows]

    def r_tokens(self, req: Request) -> dict:
        """Your API tokens (never their secrets)."""
        p = self.require(req)
        return {"tokens": self._token_list("t.user_id = ?", (p.uid,)), "prefix": tokens.PREFIX,
                "scopes": list(tokens.SCOPES), "default_days": tokens.DEFAULT_DAYS, "max_days": tokens.MAX_DAYS,
                "can_never_expire": p.user["role"] == "admin"}

    def r_token_create(self, req: Request) -> dict:
        """Create an API token for yourself (browser sign-in only). The token is in the response once."""
        p = self.require(req)
        if p.via == "token":
            raise HttpError(403, "A token cannot create tokens.")
        data = req.json()
        try:
            full, row = tokens.create(self.db, p.user, name=data.get("name", ""), scopes=data.get("scopes", ["read"]),
                                      expires_days=data.get("expires_days"), ip=req.ip, created_by=p.user["username"])
        except tokens.TokenError as e:
            raise HttpError(e.status, e.message, e.code)
        self.audit.record("api", "API token created", user=p.user, ip=req.ip, target=f"token={row['id']}",
                          detail={"name": row["name"], "scopes": row["scopes"].split(","), "expires_at": row["expires_at"]})
        return {"token": full, "info": tokens.public(row, p.user["username"])}

    def _revoke(self, req: Request, tid: str, actor: dict, owner_only: bool) -> dict:
        row = self.db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))
        if not row or (owner_only and row["user_id"] != actor["id"]):
            raise HttpError(404, "No such token.", "not_found")
        was = row["revoked_at"]
        row = tokens.revoke(self.db, tid, actor["username"])
        if not was:
            owner = self.db.user(row["user_id"])
            self.audit.record("api", "API token revoked", user=actor, ip=req.ip, target=f"token={tid}",
                              detail={"name": row["name"], "owner": owner["username"] if owner else row["user_id"]})
        return tokens.public(row)

    def r_token_revoke(self, req: Request, id: str) -> dict:
        """Revoke one of your tokens. Immediate and permanent."""
        p = self.require(req)
        return {"token": self._revoke(req, id, p.user, owner_only=True)}

    def r_token_rotate(self, req: Request, id: str) -> dict:
        """Replace a token with a new one (same name, scopes and expiry period); the old one is revoked."""
        p = self.require(req)
        row = self.db.one("SELECT * FROM api_tokens WHERE id = ?", (id,))
        if not row or row["user_id"] != p.uid:
            raise HttpError(404, "No such token.", "not_found")
        try:
            full, new, old = tokens.rotate(self.db, id, p.user, ip=req.ip, by=p.user["username"])
        except tokens.TokenError as e:
            raise HttpError(e.status, e.message, e.code)
        self.audit.record("api", "API token rotated", user=p.user, ip=req.ip, target=f"token={id}",
                          detail={"name": old["name"], "new_token": new["id"]})
        return {"token": full, "info": tokens.public(new, p.user["username"])}

    def r_openapi(self, req: Request) -> dict:
        """OpenAPI 3 description of this API (any valid token)."""
        self.require(req, any_scope=True)
        paths: dict[str, dict] = {}
        for r in self.routes:
            t = r["template"]
            if not t.startswith("/api/v1/"):
                continue
            scope = r["scope"] if t not in ("/api/v1/me", "/api/v1/openapi.json") else "any"
            paths.setdefault(t, {})[r["method"].lower()] = {
                "summary": (r["doc"].split("\n")[0] or t)[:120], "description": r["doc"],
                "x-required-scope": scope or "any",
                "parameters": [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                               for n in re.findall(r"\{(\w+)\}", t)],
                "responses": {"200": {"description": "OK"}, "401": {"description": "missing or invalid token"},
                              "403": {"description": "insufficient scope"}}}
        terminal = [("GET", "/api/v1/sessions", "read", "Your open terminals"),
                    ("POST", "/api/v1/sessions", "write", "Open a terminal {command, cwd, cols, rows, label}"),
                    ("POST", "/api/v1/sessions/{id}/kill", "write", "Close a terminal"),
                    ("GET", "/api/v1/sessions/{id}/where", "read", "Host, address and directory of a terminal"),
                    ("POST", "/api/v1/sessions/{id}/command", "write", "Log a command line sent to a terminal"),
                    ("GET", "/api/v1/history", "read", "History and saved connections"),
                    ("POST", "/api/v1/history/save", "write", "Save a connection {name, command, cwd}"),
                    ("POST", "/api/v1/history/forget", "write", "Forget a saved connection {name}"),
                    ("GET", "/api/v1/commands", "read", "Commands sent (?session=&connection=&q=)"),
                    ("GET", "/api/v1/connections", "read", "Every SSH destination connected to"),
                    ("GET", "/api/v1/servers", "read", "Servers studied by the server tools")]
        for m, t, scope, summary in terminal:
            paths.setdefault(t, {})[m.lower()] = {"summary": summary, "x-required-scope": scope,
                                                  "tags": ["terminal"], "responses": {"200": {"description": "OK"}}}
        return {"openapi": "3.0.3",
                "info": {"title": f"{APP_NAME} API", "version": __version__,
                         "description": "Everything the UI does, as JSON. Authenticate with `Authorization: Bearer "
                                        f"{tokens.PREFIX}_<id>_<secret>`. Errors are "
                                        "`{\"error\": \"<code>\", \"message\": \"<text>\"}`. See docs/API.md."},
                "servers": [{"url": self.base_url(req)}],
                "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer",
                                                              "bearerFormat": f"{tokens.PREFIX}_<id>_<secret>"}}},
                "security": [{"bearer": []}], "paths": paths}

    # ─── admin ───────────────────────────────────────────────────────────────

    def _admin(self, req: Request) -> Principal:
        return self.require(req, admin=True)

    def _users_only(self) -> None:
        if self.mode != "users":
            raise HttpError(404, "There are no users to manage on the desktop; it has no sign-in.")

    def a_summary(self, req: Request) -> dict:
        """Counts for the overview: users, people online, sign-ins and failures in the last 24 hours."""
        self._admin(req)
        t = time.time()
        q = lambda sql, p=(): (self.db.one(sql, p) or {}).get("n", 0)  # noqa: E731
        term = self.hooks.get("terminals", lambda: [])()
        return {"mode": self.mode, "version": __version__,
                "users": q("SELECT COUNT(*) AS n FROM users WHERE builtin = 0"),
                "admins": q("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND builtin = 0"),
                "disabled": q("SELECT COUNT(*) AS n FROM users WHERE disabled = 1"),
                "mfa_enabled": q("SELECT COUNT(*) AS n FROM users WHERE totp_enabled = 1"),
                "active_now": q("SELECT COUNT(DISTINCT user_id) AS n FROM sessions WHERE ended_at IS NULL "
                                "AND expires_at > ? AND last_seen > ?", (t, t - ACTIVE_WINDOW)),
                "signins_24h": q("SELECT COUNT(*) AS n FROM sessions WHERE created_at > ? AND stage = 'full'", (t - 86400,)),
                "failures_24h": q("SELECT COUNT(*) AS n FROM audit WHERE category = 'auth' AND outcome IN "
                                  "('fail', 'denied') AND ts > ?", (t - 86400,)),
                "events_24h": q("SELECT COUNT(*) AS n FROM audit WHERE ts > ?", (t - 86400,)),
                "terminals": sum(1 for x in term if x.get("alive")),
                "backup_last_ok_at": self.backup.state().get("last_ok_at")}

    def a_users(self, req: Request) -> dict:
        """Every account, with whether it is online and how many terminals it has open."""
        self._admin(req)
        self._users_only()
        t = time.time()
        online = {r["user_id"] for r in self.db.all(
            "SELECT DISTINCT user_id FROM sessions WHERE ended_at IS NULL AND expires_at > ? AND last_seen > ?",
            (t, t - ACTIVE_WINDOW))}
        counts: dict[int, int] = {}
        for x in self.hooks.get("terminals", lambda: [])():
            if x.get("alive") and x.get("owner_id") is not None:
                counts[x["owner_id"]] = counts.get(x["owner_id"], 0) + 1
        rows = self.db.all("SELECT * FROM users WHERE builtin = 0 ORDER BY username COLLATE NOCASE")
        return {"users": [self.public_user(u) | {"online": u["id"] in online, "terminals": counts.get(u["id"], 0)}
                          for u in rows]}

    def _validate_user(self, data: dict, partial: bool) -> dict:
        out: dict[str, Any] = {}
        if "username" in data or not partial:
            username = str(data.get("username", "")).strip()
            if not _USERNAME_RE.fullmatch(username):
                raise HttpError(400, "Username: 1-128 characters, letters, digits and . _ @ + -")
            out["username"] = username
        for f, n in (("display_name", 200), ("email", 200)):
            if f in data:
                out[f] = str(data.get(f) or "").strip()[:n]
        if out.get("email") and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", out["email"]):
            raise HttpError(400, "Email address is not valid.")
        if "role" in data or not partial:
            role = str(data.get("role", "user"))
            if role not in ("admin", "user"):
                raise HttpError(400, "Role must be admin or user.")
            out["role"] = role
        if "auth_source" in data or not partial:
            src = str(data.get("auth_source", "local"))
            if src not in ("local", "saml", "oidc", "ldap"):
                raise HttpError(400, "Sign-in method must be local, oidc, saml or ldap.")
            out["auth_source"] = src
        for f in ("disabled", "must_change"):
            if f in data:
                out[f] = 1 if data.get(f) else 0
        return out

    def _target(self, uid: str) -> dict:
        try:
            u = self.db.user(int(uid))
        except ValueError:
            u = None
        if not u or u.get("builtin"):
            raise HttpError(404, "No such user.", "not_found")
        return u

    def a_user_create(self, req: Request) -> dict:
        """Create an account. A local account without a password gets a generated one (shown once)."""
        p = self._admin(req)
        self._users_only()
        data = req.json()
        f = self._validate_user(data, partial=False)
        if self.db.user_by_name(f["username"]):
            raise HttpError(409, f"User {f['username']} already exists.")
        password, generated = str(data.get("password") or ""), False
        if f["auth_source"] == "local":
            if not password:
                password, generated = passwords.generate(), True
            err = passwords.policy_error(password, f["username"])
            if err:
                raise HttpError(400, err)
        t = time.time()
        must_change = 1 if (generated or data.get("must_change", True)) and f["auth_source"] == "local" else 0
        self.db.execute(
            "INSERT INTO users (username, display_name, email, role, auth_source, password_hash, must_change, disabled, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (f["username"], f.get("display_name", ""), f.get("email", ""), f["role"], f["auth_source"],
             passwords.hash_password(password) if f["auth_source"] == "local" else "", must_change,
             f.get("disabled", 0), t, t))
        user = self.db.user_by_name(f["username"])
        self.audit.record("admin", "User created", user=p.user, ip=req.ip, target=f"user={f['username']}",
                          detail={k: v for k, v in f.items() if k != "username"} | {"must_change": bool(must_change)})
        return {"user": self.public_user(user), "password": password if generated else ""}

    def a_user_update(self, req: Request, id: str) -> dict:
        """Change an account: name, email, role, sign-in method, disabled, must change password."""
        p = self._admin(req)
        self._users_only()
        target = self._target(id)
        f = self._validate_user(req.json(), partial=True)
        if "username" in f and f["username"].lower() != target["username"].lower() and self.db.user_by_name(f["username"]):
            raise HttpError(409, f"User {f['username']} already exists.")
        demoting = f.get("role", target["role"]) != "admin" or f.get("disabled", target["disabled"])
        if target["role"] == "admin" and demoting and self.db.count_admins(exclude_id=target["id"]) == 0:
            raise HttpError(400, "This is the last active administrator; promote someone else first.")
        if target["id"] == p.uid and f.get("disabled"):
            raise HttpError(400, "You cannot disable your own account.")
        if f.get("auth_source") == "local" and target["auth_source"] != "local" and not target["password_hash"]:
            f["must_change"] = 1
        if f.get("auth_source") and f["auth_source"] != target["auth_source"]:
            f["external_subject"] = ""
        changes = {k: v for k, v in f.items() if target.get(k) != v}
        if changes:
            sets = ", ".join(f"{k} = ?" for k in changes) + ", updated_at = ?"
            self.db.execute(f"UPDATE users SET {sets} WHERE id = ?", (*changes.values(), time.time(), target["id"]))
            self._invalidate()
            self.audit.record("admin", "User updated", user=p.user, ip=req.ip, target=f"user={target['username']}",
                              detail={k: {"from": target.get(k), "to": v} for k, v in changes.items()})
        if changes.get("disabled") or "role" in changes or "auth_source" in changes:
            n = self.end_sessions(target["id"], "account changed by administrator")
            if changes.get("disabled"):
                self.hooks.get("user_disabled", lambda uid: 0)(target["id"])
            if n:
                self.audit.record("admin", "User signed out", user=p.user, target=f"user={target['username']}",
                                  detail={"sessions_ended": n, "reason": "account changed"})
        return {"user": self.public_user(self.db.user(target["id"]))}

    def a_user_password(self, req: Request, id: str) -> dict:
        """Set or generate a new password for a local account (the user changes it at the next sign-in)."""
        p = self._admin(req)
        self._users_only()
        target = self._target(id)
        if target["auth_source"] != "local":
            raise HttpError(400, "This account signs in through its directory or identity provider. "
                                 "Switch it to local first if it should have a password here.")
        data = req.json()
        password, generated = str(data.get("password") or ""), False
        if not password:
            password, generated = passwords.generate(), True
        err = passwords.policy_error(password, target["username"])
        if err:
            raise HttpError(400, err)
        must_change = 1 if (generated or data.get("must_change", True)) else 0
        self.db.execute("UPDATE users SET password_hash = ?, must_change = ?, updated_at = ? WHERE id = ?",
                        (passwords.hash_password(password), must_change, time.time(), target["id"]))
        n = self.end_sessions(target["id"], "password reset by administrator") if target["id"] != p.uid else 0
        self.audit.record("admin", "Password reset", user=p.user, ip=req.ip, target=f"user={target['username']}",
                          detail={"must_change": bool(must_change), "sessions_ended": n})
        return {"ok": True, "password": password if generated else ""}

    def a_user_signout(self, req: Request, id: str) -> dict:
        """End every sign-in of a user and close their terminals."""
        p = self._admin(req)
        self._users_only()
        target = self._target(id)
        n = self.end_sessions(target["id"], "signed out by administrator",
                              except_sid=p.session_id if target["id"] == p.uid else "")
        killed = self.hooks.get("user_disabled", lambda uid: 0)(target["id"]) if target["id"] != p.uid else 0
        self.audit.record("admin", "User signed out", user=p.user, ip=req.ip, target=f"user={target['username']}",
                          detail={"sessions_ended": n, "terminals_closed": killed})
        return {"ok": True, "sessions_ended": n, "terminals_closed": killed}

    def a_user_mfa_reset(self, req: Request, id: str) -> dict:
        """Remove a user's authenticator (lost phone). They enrol again at the next sign-in when required."""
        p = self._admin(req)
        self._users_only()
        target = self._target(id)
        self.db.execute("UPDATE users SET totp_enabled = 0, totp_secret_enc = '', recovery_codes = '[]', "
                        "totp_last_step = 0, updated_at = ? WHERE id = ?", (time.time(), target["id"]))
        n = self.end_sessions(target["id"], "2FA reset by administrator") if target["id"] != p.uid else 0
        self.audit.record("admin", "2FA reset", user=p.user, ip=req.ip, target=f"user={target['username']}",
                          detail={"sessions_ended": n})
        return {"ok": True}

    def a_user_delete(self, req: Request, id: str) -> dict:
        """Delete an account, its tokens, terminals and data. Audit rows keep its name."""
        p = self._admin(req)
        self._users_only()
        target = self._target(id)
        if target["id"] == p.uid:
            raise HttpError(400, "You cannot delete your own account.")
        if target["role"] == "admin" and self.db.count_admins(exclude_id=target["id"]) == 0:
            raise HttpError(400, "This is the last active administrator.")
        self.end_sessions(target["id"], "account deleted")
        self.hooks.get("user_deleted", lambda uid: None)(target["id"])
        n_tokens = self.db.execute("DELETE FROM api_tokens WHERE user_id = ?", (target["id"],)).rowcount or 0
        self.db.execute("DELETE FROM users WHERE id = ?", (target["id"],))
        self._invalidate()
        self.audit.record("admin", "User deleted", user=p.user, ip=req.ip, target=f"user={target['username']}",
                          detail={"role": target["role"], "auth_source": target["auth_source"],
                                  "api_tokens_deleted": n_tokens})
        return {"ok": True}

    def _session_rows(self, where: str = "", params: tuple = (), limit: int = 200) -> list[dict]:
        return self.db.all(
            "SELECT s.created_at, s.last_seen, s.expires_at, s.ended_at, s.end_reason, s.method, s.stage, s.ip, "
            "s.user_agent, s.user_id, substr(s.id, 1, 12) AS sid, u.username, u.display_name "
            "FROM sessions s LEFT JOIN users u ON u.id = s.user_id "
            + (f"WHERE {where} " if where else "") + "ORDER BY s.created_at DESC LIMIT ?",
            (*params, max(1, min(limit, 2000))))

    def a_active(self, req: Request) -> dict:
        """Who is signed in and active in the last five minutes."""
        self._admin(req)
        t = time.time()
        return {"sessions": self._session_rows("s.ended_at IS NULL AND s.expires_at > ? AND s.last_seen > ?",
                                               (t, t - ACTIVE_WINDOW), 500), "window": ACTIVE_WINDOW}

    def a_sessions(self, req: Request) -> dict:
        """Sign-in history (?user_id=&limit=)."""
        self._admin(req)
        limit = _int_in(req.q("limit", "200"), 1, 2000, "limit")
        uid = req.q("user_id")
        if uid.isdigit():
            return {"sessions": self._session_rows("s.user_id = ?", (int(uid),), limit)}
        return {"sessions": self._session_rows(limit=limit)}

    def a_terminals(self, req: Request) -> dict:
        """Every terminal on this server, with its owner."""
        self._admin(req)
        names = {u["id"]: u["username"] for u in self.db.all("SELECT id, username FROM users")}
        rows = self.hooks.get("terminals", lambda: [])()
        for r in rows:
            r["owner"] = names.get(r.get("owner_id"), "")
        return {"terminals": rows}

    def a_terminal_kill(self, req: Request, id: str) -> dict:
        """Close any terminal (its process is ended)."""
        p = self._admin(req)
        info = self.hooks.get("kill_terminal", lambda sid: None)(id)
        if info is None:
            raise HttpError(404, "No such terminal.", "not_found")
        self.audit.record("admin", "Terminal closed by administrator", user=p.user, ip=req.ip,
                          target=f"terminal={id}", detail=info)
        return {"ok": True}

    def _filters(self, req: Request) -> dict:
        def num(name: str) -> float | None:
            v = req.q(name)
            try:
                return float(v) if v not in (None, "") else None
            except ValueError:
                raise HttpError(400, f"{name} must be a number")
        uid = req.q("user_id")
        return {"user_id": int(uid) if uid.isdigit() else None, "username": req.q("username")[:128],
                "category": req.q("category")[:20], "outcome": req.q("outcome")[:20], "q": req.q("q")[:200],
                "action": req.q("action")[:200], "path": req.q("path")[:300], "token_id": req.q("token_id")[:16],
                "method": req.q("method")[:10], "since": num("since"), "until": num("until")}

    def _page_args(self, req: Request) -> dict:
        b = req.q("before_id")
        return {"limit": _int_in(req.q("limit", "200"), 1, 5000, "limit"),
                "before_id": int(b) if b.isdigit() else None}

    def a_audit(self, req: Request) -> dict:
        """Audit stream: security events. Filters: since, until (epoch s), username, user_id, category,
        outcome, action, path, token_id, q; page with before_id."""
        self._admin(req)
        f = {k: v for k, v in self._filters(req).items() if k != "method"}
        return {"events": self.audit.query(**f, **self._page_args(req))}

    def a_activity(self, req: Request) -> dict:
        """Activity stream: every state-changing request and API call. Filters: since, until, username,
        user_id, outcome (ok|fail), method, path, token_id, q; page with before_id."""
        self._admin(req)
        return {"events": self.activity.query(**self._filters(req), **self._page_args(req))}

    def a_export(self, req: Request, stream: str, fmt: str) -> Response:
        """The filtered audit or activity view as CSV or NDJSON (ECS events), at most 5,000 rows."""
        p = self._admin(req)
        f = self._filters(req)
        rows = self.audit.query(**{k: v for k, v in f.items() if k != "method"}, limit=5000) if stream == "audit" \
            else self.activity.query(**f, limit=5000)
        name = f"{KEY}-{stream}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.{fmt}"
        self.audit.record("admin", "Audit log exported", user=p.user, ip=req.ip,
                          detail={"stream": stream, "format": fmt, "rows": len(rows),
                                  "filters": {k: v for k, v in f.items() if v not in (None, "")}})
        disp = ("Content-Disposition", f'attachment; filename="{name}"')
        if fmt == "json":
            conv = LOG.audit_event if stream == "audit" else LOG.activity_event
            body = "\n".join(json.dumps(conv(r), separators=(",", ":"), default=str) for r in rows)
            return Response(200, (body + ("\n" if body else "")).encode(), "application/x-ndjson", [disp])
        buf = io.StringIO()
        w = csv.writer(buf)
        if stream == "audit":
            w.writerow(["id", "time_utc", "username", "token_id", "ip", "category", "action", "target", "outcome",
                        "status", "user_agent", "detail"])
            for r in rows:
                w.writerow([r["id"], _utc(r["ts"]), r["username"], r["token_id"], r["ip"], r["category"], r["action"],
                            r["target"], r["outcome"], r["status"] or "", r["user_agent"],
                            json.dumps(r["detail"], default=str)])
        else:
            w.writerow(["id", "time_utc", "username", "token_id", "ip", "method", "path", "status", "duration_ms",
                        "user_agent"])
            for r in rows:
                w.writerow([r["id"], _utc(r["ts"]), r["username"], r["token_id"], r["ip"], r["method"], r["path"],
                            r["status"], r["duration_ms"], r["user_agent"]])
        return Response(200, buf.getvalue().encode(), "text/csv; charset=utf-8", [disp])

    def a_tokens(self, req: Request) -> dict:
        """Every user's API tokens (never their secrets)."""
        self._admin(req)
        return {"tokens": self._token_list()}

    def a_token_revoke(self, req: Request, id: str) -> dict:
        """Revoke any user's token. Immediate and permanent."""
        p = self._admin(req)
        return {"token": self._revoke(req, id, p.user, owner_only=False)}

    # ── log forwarding ──
    def _stored_dests(self) -> list[dict]:
        return list(self.db.get_setting("log_forwarding", []) or [])

    @staticmethod
    def _dest_summary(cfg: dict) -> dict:
        keep = ("name", "type", "enabled", "streams", "min_level", "host", "port", "transport", "facility", "url",
                "batch_size", "timeout", "verify_tls")
        out = {k: cfg[k] for k in keep if k in cfg}
        out["auth_header"] = "set" if cfg.get("auth_enc") else "none"
        out["ca"] = bool(cfg.get("ca_pem"))
        return out

    def a_logging(self, req: Request) -> dict:
        """JSON log settings and every forwarding destination with its counters (no credentials)."""
        self._admin(req)
        status = LOG.status()
        return {"stdout_json": LOG.json, "environment": LOG.environment, "dataset_prefix": LOG.key,
                "file": str(LOG.file_path.name) if LOG.file_path else "",
                "streams": list(logs_mod.STREAMS), "levels": list(logs_mod.LEVELS),
                "facilities": list(logs_mod.FACILITIES),
                "destinations": [logs_mod.public_destination(d, status.get(d["id"])) for d in LOG.destinations()]}

    def a_log_add(self, req: Request) -> dict:
        """Add a syslog or HTTP(S) destination. Forwarding starts at the current end of the log."""
        p = self._admin(req)
        try:
            cfg = logs_mod.validate(req.json(), None, LOG)
        except ValueError as e:
            raise HttpError(400, str(e))
        LOG.init_cursor(cfg["id"])
        self.db.set_setting("log_forwarding", self._stored_dests() + [cfg])
        LOG.reload()
        self.audit.record("admin", "Log forwarding destination added", user=p.user, ip=req.ip,
                          target=f"destination={cfg['name']}", detail=self._dest_summary(cfg))
        return {"destination": logs_mod.public_destination(cfg, None)}

    def _find_dest(self, did: str) -> tuple[list[dict], int]:
        if did == "env":
            raise HttpError(400, "This destination comes from the environment (LOG_FORWARD_URL); change it in the deployment.")
        dests = self._stored_dests()
        for i, d in enumerate(dests):
            if d["id"] == did:
                return dests, i
        raise HttpError(404, "No such destination.", "not_found")

    def a_log_update(self, req: Request, id: str) -> dict:
        """Change a destination. Send auth_header to replace the header, "" to remove it, omit to keep."""
        p = self._admin(req)
        data = req.json()
        dests, i = self._find_dest(id)
        old = dests[i]
        try:
            cfg = logs_mod.validate(data, old, LOG)
        except ValueError as e:
            raise HttpError(400, str(e))
        dests[i] = cfg
        self.db.set_setting("log_forwarding", dests)
        LOG.reload()
        a, b = self._dest_summary(old), self._dest_summary(cfg)
        if old.get("auth_enc") != cfg.get("auth_enc"):
            b["auth_header"] = "changed" if cfg.get("auth_enc") else "removed"
        self.audit.record("admin", "Log forwarding destination changed", user=p.user, ip=req.ip,
                          target=f"destination={cfg['name']}",
                          detail={k: {"from": a.get(k), "to": b.get(k)} for k in b if a.get(k) != b.get(k)})
        return {"destination": logs_mod.public_destination(cfg, LOG.status().get(cfg["id"]))}

    def a_log_delete(self, req: Request, id: str) -> dict:
        """Remove a destination and its delivery cursor."""
        p = self._admin(req)
        dests, i = self._find_dest(id)
        gone = dests.pop(i)
        self.db.set_setting("log_forwarding", dests)
        LOG.reload()
        LOG.drop_cursor(id)
        self.audit.record("admin", "Log forwarding destination removed", user=p.user, ip=req.ip,
                          target=f"destination={gone['name']}", detail=self._dest_summary(gone))
        return {"ok": True}

    def a_log_test(self, req: Request, id: str) -> dict:
        """Send one test event (dataset <key>.app, event.action "test") and report the result."""
        p = self._admin(req)
        cfg = next((d for d in LOG.destinations() if d["id"] == id), None)
        if not cfg:
            raise HttpError(404, "No such destination.", "not_found")
        err = LOG.test(cfg, p.user["username"])
        self.audit.record("admin", "Log forwarding test event sent", user=p.user, ip=req.ip,
                          target=f"destination={cfg['name']}", outcome="error" if err else "ok",
                          detail={"error": err} if err else {})
        return {"ok": not err, "error": err}

    # ── settings: policy and single sign-on ──
    @staticmethod
    def _hide(cfg: dict, field_: str, public: str) -> dict:
        out = {k: v for k, v in cfg.items() if k != field_}
        out[public] = "set" if cfg.get(field_) else ""
        return out

    def a_settings(self, req: Request) -> dict:
        """Policy, SAML, OpenID Connect and LDAP settings (secrets shown only as "set"), and this service's URLs."""
        self._admin(req)
        base = self.base_url(req)
        return {"mode": self.mode, "policy": self.policy(), "saml": self.saml_cfg(),
                "oidc": self._hide(self.oidc_cfg(), "client_secret_enc", "client_secret"),
                "ldap": self._hide(self.ldap_cfg(), "bind_password_enc", "bind_password"),
                "public_url": self.public_url(), "public_url_from_env": bool(os.environ.get("ARES_PUBLIC_URL")),
                "sp": {"entity_id": self._sp_entity(req), "acs_url": base + "/saml/acs",
                       "metadata_url": base + "/saml/metadata", "sign_on_url": base + "/saml/login"},
                "oidc_redirect_uri": base + "/auth/oidc/callback"}

    def a_policy(self, req: Request) -> dict:
        """Sessions, lockout, retention, two-factor requirement and who may open a shell on this server."""
        p = self._admin(req)
        data = req.json()
        old = self.policy()
        new = dict(old)
        limits = {"session_idle_minutes": (5, 1440), "session_max_hours": (1, 720), "audit_retention_days": (7, 3650),
                  "activity_retention_days": (7, 3650), "lockout_threshold": (3, 100), "lockout_minutes": (1, 1440)}
        for k, (lo, hi) in limits.items():
            if k in data:
                new[k] = _int_in(data[k], lo, hi, k)
        for k, allowed in (("local_login", ("enabled", "admins_only")), ("mfa_required", ("all", "admins", "optional")),
                           ("local_shell", ("all", "admins", "none"))):
            if k in data:
                if data[k] not in allowed:
                    raise HttpError(400, f"{k} must be one of: {', '.join(allowed)}")
                new[k] = data[k]
        if "mfa_for_sso" in data:
            new["mfa_for_sso"] = bool(data["mfa_for_sso"])
        self.db.set_setting("policy", {k: new[k] for k in DEFAULT_POLICY})
        if "public_url" in data and not os.environ.get("ARES_PUBLIC_URL"):
            pu = str(data["public_url"] or "").strip().rstrip("/")
            if pu and not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d+)?", pu):
                raise HttpError(400, "Public URL must look like https://host[:port] with no path")
            self.db.set_setting("public_url", pu)
        self._invalidate()
        diff = {k: {"from": old.get(k), "to": new[k]} for k in DEFAULT_POLICY if old.get(k) != new[k]}
        self.audit.record("admin", "Policy changed", user=p.user, ip=req.ip, detail=diff)
        return {"policy": self.policy()}

    def _sso_common(self, data: dict, new: dict) -> None:
        for k in ("auto_provision", "sync_role", "enabled"):
            if k in data:
                new[k] = bool(data[k])
        if "default_role" in data:
            if data["default_role"] not in ("admin", "user"):
                raise HttpError(400, "default_role must be admin or user")
            new["default_role"] = data["default_role"]
        for k in ("admin_groups", "allowed_groups"):
            if k in data:
                new[k] = _norm_list(data[k])
        if "button_label" in data:
            new["button_label"] = str(data["button_label"] or "").strip()[:80]

    def a_saml(self, req: Request) -> dict:
        """SAML 2.0 identity provider settings."""
        p = self._admin(req)
        self._users_only()
        from . import saml
        data = req.json()
        old = self.saml_cfg()
        new = dict(old)
        for k in ("metadata_url", "idp_entity_id", "idp_sso_url", "idp_slo_url", "sp_entity_id"):
            if k in data:
                new[k] = str(data[k] or "").strip()[:1000]
        if "allow_idp_initiated" in data:
            new["allow_idp_initiated"] = bool(data["allow_idp_initiated"])
        if "username_claim" in data:
            if data["username_claim"] not in ("upn", "email", "nameid"):
                raise HttpError(400, "username_claim must be upn, email or nameid")
            new["username_claim"] = data["username_claim"]
        self._sso_common(data, new)
        if "idp_certs" in data:
            raw = data["idp_certs"]
            blocks = raw if isinstance(raw, list) else re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", str(raw), re.S) or \
                ([str(raw)] if str(raw).strip() else [])
            try:
                new["idp_certs"] = [c for c in (saml.normalize_cert(b) for b in blocks) if c]
            except saml.SamlError as e:
                raise HttpError(400, f"IdP certificate: {e}")
            from cryptography import x509
            for pem in new["idp_certs"]:
                try:
                    x509.load_pem_x509_certificate(pem.encode())
                except ValueError:
                    raise HttpError(400, "An IdP certificate could not be parsed.")
        for k in ("idp_sso_url", "idp_slo_url", "metadata_url"):
            if new[k] and not new[k].lower().startswith("https://"):
                raise HttpError(400, f"{k} must be an https:// URL")
        if new["enabled"] and not (new["idp_entity_id"] and new["idp_sso_url"] and new["idp_certs"]):
            raise HttpError(400, "To enable SAML, set the IdP entity ID, sign-on URL and certificate "
                                 "(load them from the IdP's federation metadata).")
        self.db.set_setting("saml", {k: new[k] for k in DEFAULT_SAML})
        diff = {k: {"from": old.get(k), "to": new[k]} for k in DEFAULT_SAML if old.get(k) != new[k] and k != "idp_certs"}
        if old.get("idp_certs") != new["idp_certs"]:
            diff["idp_certs"] = {"count": len(new["idp_certs"])}
        self.audit.record("admin", "SAML settings changed", user=p.user, ip=req.ip, detail=diff)
        return {"saml": self.saml_cfg()}

    def a_saml_metadata(self, req: Request) -> dict:
        """Parse IdP federation metadata (from its URL or pasted XML). Does not save."""
        self._admin(req)
        from . import saml
        data = req.json()
        try:
            if data.get("xml"):
                return saml.parse_metadata(str(data["xml"]).encode("utf-8"))
            url = str(data.get("url") or "").strip()
            parsed = saml.parse_metadata(saml.fetch_metadata(url))
            parsed["metadata_url"] = url
            return parsed
        except saml.SamlError as e:
            raise HttpError(400, str(e))

    def a_oidc(self, req: Request) -> dict:
        """Microsoft Entra ID / OpenID Connect settings. client_secret: omit to keep, "" to remove."""
        p = self._admin(req)
        self._users_only()
        data = req.json()
        old = self.oidc_cfg()
        new = dict(old)
        if "provider" in data:
            if data["provider"] not in ("entra", "generic"):
                raise HttpError(400, "provider must be entra or generic")
            new["provider"] = data["provider"]
        for k in ("tenant_id", "discovery_url", "client_id", "scopes", "groups_claim"):
            if k in data:
                new[k] = str(data[k] or "").strip()[:1000]
        if "username_claim" in data:
            if data["username_claim"] not in ("preferred_username", "email", "upn", "sub"):
                raise HttpError(400, "username_claim must be preferred_username, email, upn or sub")
            new["username_claim"] = data["username_claim"]
        self._sso_common(data, new)
        if new.get("tenant_id") and not re.fullmatch(r"[A-Za-z0-9.-]{1,100}", new["tenant_id"]):
            raise HttpError(400, "Tenant: the directory (tenant) ID or a verified domain such as contoso.com.")
        if new.get("discovery_url") and not new["discovery_url"].lower().startswith("https://"):
            raise HttpError(400, "The discovery URL must be https://")
        if "client_secret" in data and data["client_secret"] is not None:
            v = str(data["client_secret"])
            new["client_secret_enc"] = self.sso_sealer.seal(v) if v.strip() else ""
        if new["enabled"] and not self._oidc_ready(new):
            raise HttpError(400, "To enable it, set the tenant (or discovery URL), the client ID and the client secret.")
        self.db.set_setting("oidc", new)
        diff = {k: {"from": old.get(k), "to": new[k]} for k in new if old.get(k) != new[k] and k != "client_secret_enc"}
        if old.get("client_secret_enc") != new.get("client_secret_enc"):
            diff["client_secret"] = "changed" if new.get("client_secret_enc") else "removed"
        self.audit.record("admin", "OpenID Connect settings changed", user=p.user, ip=req.ip, detail=diff)
        return {"oidc": self._hide(self.oidc_cfg(), "client_secret_enc", "client_secret")}

    def a_oidc_test(self, req: Request) -> dict:
        """Fetch the provider's discovery document and signing keys with the saved settings."""
        p = self._admin(req)
        from . import oidc
        try:
            msg, err = oidc.test(self.oidc_cfg()), ""
        except Exception as e:  # noqa: BLE001
            msg, err = "", str(e)[:500]
        self.audit.record("admin", "OpenID Connect settings tested", user=p.user, ip=req.ip,
                          outcome="error" if err else "ok", detail={"error": err} if err else {})
        return {"ok": not err, "message": msg, "error": err}

    def a_ldap(self, req: Request) -> dict:
        """LDAP / Active Directory settings. bind_password: omit to keep, "" to remove."""
        p = self._admin(req)
        self._users_only()
        data = req.json()
        old = self.ldap_cfg()
        new = dict(old)
        for k in ("server_url", "bind_dn", "base_dn", "user_filter", "username_attr", "email_attr", "name_attr",
                  "group_attr", "ca_pem"):
            if k in data:
                new[k] = str(data[k] or "").strip()[:8000 if k == "ca_pem" else 1000]
        for k in ("start_tls", "verify_tls"):
            if k in data:
                new[k] = bool(data[k])
        if "timeout" in data:
            new["timeout"] = _int_in(data["timeout"], 2, 60, "timeout")
        self._sso_common(data, new)
        for u in re.split(r"[\s,]+", new.get("server_url") or ""):
            if u and not re.fullmatch(r"ldaps?://[A-Za-z0-9.\-\[\]:]+(:\d+)?/?", u):
                raise HttpError(400, "Server URL: ldaps://host:636 or ldap://host:389 (several separated by spaces).")
        if new.get("user_filter") and "{username}" not in new["user_filter"]:
            raise HttpError(400, "The user filter must contain {username}.")
        if "bind_password" in data and data["bind_password"] is not None:
            v = str(data["bind_password"])
            new["bind_password_enc"] = self.sso_sealer.seal(v) if v else ""
        if new["enabled"] and not (new.get("server_url") and new.get("base_dn")):
            raise HttpError(400, "To enable LDAP, set the server URL and the base DN.")
        self.db.set_setting("ldap", new)
        diff = {k: {"from": old.get(k), "to": new[k]} for k in new
                if old.get(k) != new[k] and k not in ("bind_password_enc", "ca_pem")}
        if old.get("bind_password_enc") != new.get("bind_password_enc"):
            diff["bind_password"] = "changed" if new.get("bind_password_enc") else "removed"
        if old.get("ca_pem") != new.get("ca_pem"):
            diff["ca_pem"] = "changed"
        self.audit.record("admin", "LDAP settings changed", user=p.user, ip=req.ip, detail=diff)
        return {"ldap": self._hide(self.ldap_cfg(), "bind_password_enc", "bind_password")}

    def a_ldap_test(self, req: Request) -> dict:
        """Connect and bind with the saved settings; with {username, password} also try that sign-in."""
        p = self._admin(req)
        from . import ldapauth
        data = req.json()
        cfg = self.ldap_cfg()
        try:
            msg, err = ldapauth.test(cfg, self._open_secret(cfg.get("bind_password_enc", "")),
                                     str(data.get("username") or ""), str(data.get("password") or "")), ""
        except Exception as e:  # noqa: BLE001
            msg, err = "", str(e)[:500]
        self.audit.record("admin", "LDAP settings tested", user=p.user, ip=req.ip, outcome="error" if err else "ok",
                          detail={"error": err, "username": str(data.get("username") or "")[:100]})
        return {"ok": not err, "message": msg, "error": err}

    # ── backup & restore ──
    def _actor(self, req: Request, p: Principal) -> dict:
        return {"id": p.uid, "username": p.user["username"], "ip": req.ip}

    def _last_result(self, st: dict, did: str) -> dict | None:
        for h in st.get("history", []):
            for r in h.get("results", []):
                if r.get("id") == did:
                    return {"at": h["at"], "name": h["name"], "ok": r["ok"], "error": r["error"],
                            "pruned": len(r.get("pruned", []))}
        return None

    def backup_view(self) -> dict:
        cfg, st = self.backup.config(), self.backup.state()
        return {"key": KEY, "version": __version__, "timezone": backup.server_timezone(),
                "passphrase_set": bool(self.backup.passphrase()), "min_passphrase": backup.MIN_PASSPHRASE,
                "schedule": cfg["schedule"], "schedule_text": backup.describe_schedule(cfg["schedule"]),
                "next_run_at": self.backup.next_run_at(), "running": self.backup.running,
                "destinations": [backup.public_destination(d) | {"last": self._last_result(st, d["id"])}
                                 for d in cfg["destinations"]],
                "last": st.get("last"), "last_ok_at": st.get("last_ok_at"), "history": st.get("history", [])[:10],
                "restore_pending": (self.data_dir / ".restore-pending").exists(), "mode": self.mode}

    def a_backup(self, req: Request) -> dict:
        """Backup status: passphrase set or not, schedule, destinations with their last result, history."""
        self._admin(req)
        return self.backup_view()

    def a_backup_schedule(self, req: Request) -> dict:
        """Set the schedule: mode off | hourly | every (hours) | daily (time) | weekly (weekday 0=Mon, time)."""
        p = self._admin(req)
        try:
            new = backup.validate_schedule(req.json())
        except ValueError as e:
            raise HttpError(400, str(e))
        cfg = self.backup.config()
        old = cfg["schedule"]
        cfg["schedule"] = new
        self.backup.save_config(cfg)
        self.backup._save_state(schedule_since=time.time(), last_scheduled_at=None)
        self.audit.record("admin", "Backup schedule changed", user=p.user, ip=req.ip,
                          detail={"from": backup.describe_schedule(old), "to": backup.describe_schedule(new)})
        return self.backup_view()

    def a_backup_passphrase(self, req: Request) -> dict:
        """Set or change the backup passphrase ("" removes it). It is never inside a backup: keep a copy offline."""
        p = self._admin(req)
        value = str(req.json().get("passphrase") or "")
        had = bool(self.backup.passphrase())
        try:
            self.backup.set_passphrase(value)
        except ValueError as e:
            raise HttpError(400, str(e))
        self.audit.record("admin", "Backup passphrase " + ("removed" if not value else "changed" if had else "set"),
                          user=p.user, ip=req.ip)
        return self.backup_view()

    def _bdest(self, did: str) -> tuple[dict, int]:
        cfg = self.backup.config()
        for i, d in enumerate(cfg["destinations"]):
            if d["id"] == did:
                return cfg, i
        raise HttpError(404, "No such destination.", "not_found")

    @staticmethod
    def _bsum(d: dict) -> dict:
        return {k: v for k, v in backup.public_destination(d).items() if k not in ("id", "host_key", "requires_encryption")}

    def a_bdest_add(self, req: Request) -> dict:
        """Add an SFTP or S3-compatible destination. Credentials are stored encrypted and never returned."""
        p = self._admin(req)
        try:
            d = backup.validate_destination(req.json(), None, self.backup.sealer)
        except ValueError as e:
            raise HttpError(400, str(e))
        cfg = self.backup.config()
        cfg["destinations"].append(d)
        self.backup.save_config(cfg)
        self.audit.record("admin", "Backup destination added", user=p.user, ip=req.ip,
                          target=f"destination={d['name']}", detail=self._bsum(d))
        return {"destination": backup.public_destination(d)}

    def a_bdest_update(self, req: Request, id: str) -> dict:
        """Change a destination. For a secret field: omit to keep it, "" to remove it, a value to replace it."""
        p = self._admin(req)
        data = req.json()
        cfg, i = self._bdest(id)
        old = cfg["destinations"][i]
        try:
            d = backup.validate_destination(data, old, self.backup.sealer)
        except ValueError as e:
            raise HttpError(400, str(e))
        cfg["destinations"][i] = d
        self.backup.save_config(cfg)
        a, b = self._bsum(old), self._bsum(d)
        for f in ("password", "private_key", "key_passphrase", "secret_key"):
            if old.get(f + "_enc") != d.get(f + "_enc") and d.get(f + "_enc"):
                b[f] = "changed"
        self.audit.record("admin", "Backup destination changed", user=p.user, ip=req.ip,
                          target=f"destination={d['name']}",
                          detail={k: {"from": a.get(k), "to": b.get(k)} for k in set(a) | set(b) if a.get(k) != b.get(k)})
        return {"destination": backup.public_destination(d)}

    def a_bdest_delete(self, req: Request, id: str) -> dict:
        """Remove an SFTP or S3 destination from the settings (its backups stay where they are)."""
        p = self._admin(req)
        cfg, i = self._bdest(id)
        if cfg["destinations"][i]["type"] == "local":
            raise HttpError(400, "The local destination cannot be removed; disable it or set its retention.")
        gone = cfg["destinations"].pop(i)
        self.backup.save_config(cfg)
        self.audit.record("admin", "Backup destination removed", user=p.user, ip=req.ip,
                          target=f"destination={gone['name']}", detail=self._bsum(gone))
        return {"ok": True}

    def a_bdest_test(self, req: Request, id: str) -> dict:
        """Connect, write and delete a small probe file. Pins an SFTP host key on first use."""
        p = self._admin(req)
        cfg, i = self._bdest(id)
        d = cfg["destinations"][i]
        try:
            with self.backup._dest(d) as dest:
                msg, err = dest.test(), ""
        except Exception as e:  # noqa: BLE001
            msg, err = "", str(e) if isinstance(e, backup.BackupError) else f"{type(e).__name__}: {e}"
        self.audit.record("admin", "Backup destination tested", user=p.user, ip=req.ip,
                          target=f"destination={d['name']}", outcome="error" if err else "ok",
                          detail={"error": err} if err else {"result": msg})
        return {"ok": not err, "message": msg, "error": err,
                "destination": backup.public_destination(self.backup.destination_cfg(id))}

    def a_backup_list(self, req: Request, id: str) -> dict:
        """The backups in one destination, newest first."""
        self._admin(req)
        self._bdest(id)
        try:
            return {"backups": self.backup.list(id)}
        except backup.BackupError as e:
            raise HttpError(502, str(e))

    def a_backup_download(self, req: Request, id: str, name: str) -> Response:
        """Download one backup archive (to keep a copy elsewhere, or to restore on another install)."""
        p = self._admin(req)
        cfg, i = self._bdest(id)
        if not backup.NAME_RE.match(name):
            raise HttpError(400, "Not a backup name.")
        d = cfg["destinations"][i]
        after = None
        try:
            if d["type"] == "local":
                path = backup.LocalDest(self.backup.local_root).path(name)
            else:
                self.uploads.mkdir(parents=True, exist_ok=True)
                path = self.uploads / f"dl-{secrets.token_hex(6)}"
                self.backup.fetch(id, name, path)
                after = lambda p_=path: p_.unlink(missing_ok=True)  # noqa: E731
        except backup.BackupError as e:
            raise HttpError(404 if d["type"] == "local" else 502, str(e))
        self.audit.record("admin", "Backup downloaded", user=p.user, ip=req.ip, target=f"backup={name}",
                          detail={"destination": d["name"], "size": path.stat().st_size})
        return Response(200, b"", "application/octet-stream",
                        [("Content-Disposition", f'attachment; filename="{name}"')], file=path, after=after)

    def a_backup_run(self, req: Request) -> dict:
        """Back up now to every enabled destination (or {"destinations": [ids]}); waits for the result."""
        p = self._admin(req)
        data = req.json() if req.length() else {}
        only = data.get("destinations") or None
        if only is not None and (not isinstance(only, list) or not all(isinstance(x, str) for x in only)):
            raise HttpError(400, "destinations must be a list of destination ids")
        try:
            res = self.backup.create("manual", only, self._actor(req, p))
        except backup.BackupError as e:
            raise HttpError(409, str(e))
        return {"backup": res, **self.backup_view()}

    def a_backup_prune(self, req: Request) -> dict:
        """Apply every destination's retention now (the newest backup is always kept)."""
        p = self._admin(req)
        return {"results": self.backup.prune(self._actor(req, p))}

    def _sweep_uploads(self) -> None:
        if not self.uploads.is_dir():
            return
        for f in self.uploads.iterdir():
            try:
                if time.time() - f.stat().st_mtime > 3600:
                    f.unlink()
            except OSError:
                pass

    def a_backup_upload(self, req: Request) -> dict:
        """Upload an archive to restore (raw body, application/octet-stream). Returns an upload id for /restore."""
        self._admin(req)
        n = req.length()
        if n > MAX_UPLOAD:
            req.drain()
            raise HttpError(413, "The upload is too large.")
        self._sweep_uploads()
        self.uploads.mkdir(parents=True, exist_ok=True)
        os.chmod(self.uploads, 0o700)
        uid = secrets.token_hex(8)
        path = self.uploads / f"{uid}.bin"
        left = n
        with open(path, "wb") as f:
            while left > 0:
                chunk = req.h.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        req._body = b""
        if n < 64 or left:
            path.unlink(missing_ok=True)
            raise HttpError(400, "The upload is empty, incomplete or too small to be a backup.")
        label = re.sub(r"[^A-Za-z0-9._-]", "_", req.headers.get("X-Filename", ""))[:120] or f"upload-{uid}"
        (self.uploads / f"{uid}.name").write_text(label)
        return {"upload": uid, "size": n, "name": label, "encrypted": backup.is_encrypted_file(path)}

    def a_backup_restore(self, req: Request) -> dict:
        """Restore {"upload": id} or {"destination": id, "name": file}, with "passphrase" when encrypted.

        Verifies the archive (checksums, key, version), takes a local safety backup, then restarts the
        server to apply it. Everyone is signed out."""
        p = self._admin(req)
        data = req.json()
        passphrase = str(data.get("passphrase") or "")
        tmp = None
        if data.get("upload"):
            uid = str(data["upload"])
            if not re.fullmatch(r"[0-9a-f]{16}", uid) or not (self.uploads / f"{uid}.bin").is_file():
                raise HttpError(404, "No such upload (uploads are kept for an hour).")
            archive = tmp = self.uploads / f"{uid}.bin"
            nf = self.uploads / f"{uid}.name"
            label = nf.read_text() if nf.exists() else uid
        elif data.get("destination") and data.get("name"):
            cfg, i = self._bdest(str(data["destination"]))
            name = str(data["name"])
            if not backup.NAME_RE.match(name):
                raise HttpError(400, "Not a backup name.")
            label = name
            try:
                if cfg["destinations"][i]["type"] == "local":
                    archive = backup.LocalDest(self.backup.local_root).path(name)
                else:
                    self.uploads.mkdir(parents=True, exist_ok=True)
                    archive = tmp = self.uploads / f"dl-{secrets.token_hex(6)}"
                    self.backup.fetch(cfg["destinations"][i]["id"], name, archive)
            except backup.BackupError as e:
                raise HttpError(502, str(e))
        else:
            raise HttpError(400, 'Send {"upload": id} or {"destination": id, "name": "<backup file>"}.')
        try:
            info = self.backup.restore(archive, passphrase, self._actor(req, p), label)
        except backup.BackupError as e:
            raise HttpError(400, str(e))
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
                (self.uploads / f"{tmp.stem}.name").unlink(missing_ok=True)
        threading.Thread(target=self._restart_for_restore, name="restore-restart", daemon=True).start()
        return {"ok": True, "restarting": True, "restore": info}

    def _restart_for_restore(self) -> None:
        """Close the terminals, flush forwarding, then restart: the next start applies the staged restore."""
        time.sleep(0.7)
        LOG.app("warn", "restarting to apply the restore", action="backup_restart")
        try:
            self.hooks.get("shutdown", lambda: None)()
        finally:
            LOG.stop_all()
            self.db.close()
            restart = self.hooks.get("restart")
            if restart:
                restart()
            os._exit(75)       # supervised (pm2 / Kubernetes / Docker restart policy): the restart applies it


def reexec() -> None:
    """Restart this process in place (desktop app and ./run.sh)."""
    argv = list(sys.argv) if getattr(sys, "frozen", False) else [sys.executable] + list(sys.argv)
    try:
        os.execv(argv[0] if getattr(sys, "frozen", False) else sys.executable,
                 argv if getattr(sys, "frozen", False) else argv)
    except OSError:
        pass
