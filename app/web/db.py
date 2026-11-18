"""SQLite store: users, sign-in sessions, API tokens, audit, activity, settings.

One file, ``DATA_DIR/ares-terminal-console.db``, in WAL mode. The server is a single process
(``maxReplicas: 1``): its terminals live in memory, so a process-wide lock around one connection
is all the concurrency control there is to need. Every statement is a short indexed lookup or an
append, so the lock is held for microseconds.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name     TEXT NOT NULL DEFAULT '',
    email            TEXT NOT NULL DEFAULT '',
    role             TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    auth_source      TEXT NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'saml', 'oidc', 'ldap')),
    password_hash    TEXT NOT NULL DEFAULT '',
    must_change      INTEGER NOT NULL DEFAULT 0,
    disabled         INTEGER NOT NULL DEFAULT 0,
    external_subject TEXT NOT NULL DEFAULT '',   -- IdP object id / NameID / LDAP DN
    totp_secret_enc  TEXT NOT NULL DEFAULT '',   -- sealed with APP_KEY ("mfa")
    totp_enabled     INTEGER NOT NULL DEFAULT 0,
    totp_last_step   INTEGER NOT NULL DEFAULT 0, -- replay protection
    recovery_codes   TEXT NOT NULL DEFAULT '[]', -- sha256 of each unused code
    mfa_enrolled_at  REAL,
    builtin          INTEGER NOT NULL DEFAULT 0, -- the desktop's local user
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    last_login_at    REAL,
    last_login_ip    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS users_subject ON users (auth_source, external_subject);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,          -- keyed hash of the cookie value
    user_id     INTEGER NOT NULL,
    method      TEXT NOT NULL,             -- password | ldap | saml | oidc
    stage       TEXT NOT NULL DEFAULT 'full',  -- mfa (code still owed) | full
    created_at  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    expires_at  REAL NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    ended_at    REAL,
    end_reason  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id, created_at);
CREATE INDEX IF NOT EXISTS sessions_open ON sessions (ended_at);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    user_id     INTEGER,
    username    TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL,             -- auth | admin | api | terminal | system
    action      TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    outcome     TEXT NOT NULL DEFAULT 'ok',  -- ok | fail | denied | error
    status      INTEGER,
    detail      TEXT NOT NULL DEFAULT '{}',
    session_id  TEXT NOT NULL DEFAULT '',
    token_id    TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
CREATE INDEX IF NOT EXISTS audit_user ON audit (user_id, ts);

CREATE TABLE IF NOT EXISTS activity (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    user_id      INTEGER,
    username     TEXT NOT NULL DEFAULT '',
    token_id     TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,             -- route template, e.g. /api/v1/admin/users/{id}
    status       INTEGER NOT NULL,
    duration_ms  REAL NOT NULL DEFAULT 0,
    user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS activity_ts ON activity (ts);
CREATE INDEX IF NOT EXISTS activity_user ON activity (user_id, ts);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS saml_requests (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    relay       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS saml_assertions (
    id          TEXT PRIMARY KEY,
    expires_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_states (
    id          TEXT PRIMARY KEY,           -- the state parameter
    created_at  REAL NOT NULL,
    nonce       TEXT NOT NULL,
    verifier    TEXT NOT NULL,
    next        TEXT NOT NULL DEFAULT '/'
);

CREATE TABLE IF NOT EXISTS login_failures (
    key  TEXT NOT NULL,
    ts   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_key ON login_failures (key, ts);

CREATE TABLE IF NOT EXISTS api_tokens (
    id            TEXT PRIMARY KEY,         -- 8 hex characters, public
    user_id       INTEGER NOT NULL,
    name          TEXT NOT NULL,
    secret_hash   TEXT NOT NULL,
    scopes        TEXT NOT NULL,            -- comma list of read, write, admin
    created_at    REAL NOT NULL,
    created_ip    TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT '',
    expires_at    REAL,                     -- NULL = never (administrators only)
    last_used_at  REAL,
    last_used_ip  TEXT NOT NULL DEFAULT '',
    revoked_at    REAL,
    revoked_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens (user_id);

CREATE TABLE IF NOT EXISTS leases (
    name        TEXT PRIMARY KEY,
    owner       TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    # ── primitives ──
    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql: str, params: tuple | dict = ()) -> dict | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── settings ──
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM settings WHERE key = ?", (key,))
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))

    # ── users ──
    def user(self, user_id: int) -> dict | None:
        return self.one("SELECT * FROM users WHERE id = ?", (user_id,))

    def user_by_name(self, username: str) -> dict | None:
        return self.one("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))

    def count_admins(self, exclude_id: int | None = None) -> int:
        row = self.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0 AND builtin = 0 "
                       "AND id != ?", (exclude_id if exclude_id is not None else -1,))
        return int(row["n"]) if row else 0

    def count_users(self) -> int:
        row = self.one("SELECT COUNT(*) AS n FROM users WHERE builtin = 0")
        return int(row["n"]) if row else 0


def now() -> float:
    return time.time()
