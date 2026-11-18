"""Audit trail (security events) and activity (every state-changing request and API call).

Both are append-only tables in the app's database: nothing in the UI or the API edits or deletes
a row; only the retention purge removes old ones. Each row is also emitted as an ECS JSON event
and forwarded to the configured SIEM destinations (see logs.py).

Secrets never reach the log: callers pass details without passwords, tokens, keys, cookies or
request bodies, and a token is only ever identified by its public id.
"""

from __future__ import annotations

import json
import time
from contextvars import ContextVar
from typing import Any

from .db import Database
from .logs import LOG

# Set per request by the auth check, so every audit row written while
# serving that request carries the API token id and the browser's user agent.
ACTOR_TOKEN: ContextVar[str] = ContextVar("ares_actor_token", default="")
ACTOR_UA: ContextVar[str] = ContextVar("ares_actor_ua", default="")


class Auditor:
    """Security-relevant events and console actions (the "audit" stream).

    Append-only: nothing in the UI or the API edits or deletes a row; only the
    retention purge removes old ones. Each row is also emitted as an ECS JSON
    event (dataset ``<key>.audit``) and forwarded to the SIEM.
    """

    def __init__(self, db: Database):
        self.db = db

    def record(self, category: str, action: str, *, user: dict | None = None,
               user_id: int | None = None, username: str = "", ip: str = "",
               target: str = "", outcome: str = "ok", status: int | None = None,
               detail: dict | None = None, session_id: str = "", token_id: str = "",
               user_agent: str = "") -> None:
        if user is not None:
            user_id = user.get("id")
            username = user.get("username", "")
        token_id = token_id or ACTOR_TOKEN.get()
        user_agent = user_agent or ACTOR_UA.get()
        row = {"ts": time.time(), "user_id": user_id, "username": username, "ip": ip,
               "category": category, "action": action, "target": target[:500], "outcome": outcome,
               "status": status, "detail": json.dumps(detail or {}, default=str)[:8000],
               "session_id": session_id[:16], "token_id": token_id[:16],
               "user_agent": user_agent[:300]}
        cur = self.db.execute(
            "INSERT INTO audit (ts, user_id, username, ip, category, action, target, outcome, status, "
            "detail, session_id, token_id, user_agent) VALUES (:ts, :user_id, :username, :ip, :category, "
            ":action, :target, :outcome, :status, :detail, :session_id, :token_id, :user_agent)", row)
        row["id"] = cur.lastrowid
        LOG.audit(row)

    def purge(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cutoff = time.time() - retention_days * 86400
        cur = self.db.execute("DELETE FROM audit WHERE ts < ?", (cutoff,))
        self.db.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?", (cutoff,))
        return cur.rowcount or 0

    def query(self, *, user_id: int | None = None, username: str = "", category: str = "",
              outcome: str = "", q: str = "", since: float | None = None,
              until: float | None = None, limit: int = 200, before_id: int | None = None,
              action: str = "", path: str = "", token_id: str = "") -> list[dict]:
        where, params = [], []
        if user_id is not None:
            where.append("user_id = ?"); params.append(user_id)
        if username:
            where.append("username LIKE ?"); params.append(f"%{username}%")
        if category:
            where.append("category = ?"); params.append(category)
        if outcome:
            where.append("outcome = ?"); params.append(outcome)
        if action:
            where.append("action LIKE ?"); params.append(f"%{action}%")
        if path:
            where.append("(target LIKE ? OR detail LIKE ?)"); params += [f"%{path}%"] * 2
        if token_id:
            where.append("token_id = ?"); params.append(token_id)
        if q:
            where.append("(action LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)")
            params += [f"%{q}%"] * 4
        if since is not None:
            where.append("ts >= ?"); params.append(since)
        if until is not None:
            where.append("ts < ?"); params.append(until)
        if before_id is not None:
            where.append("id < ?"); params.append(before_id)
        sql = "SELECT * FROM audit" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        rows = self.db.all(sql, tuple(params))
        for r in rows:
            try:
                r["detail"] = json.loads(r["detail"])
            except ValueError:
                pass
        return rows


class Activity:
    """Every state-changing request and every API call (the "activity" stream).

    Method, route template, status, duration, who (user and token id) and
    where from. Never bodies, query strings, headers or cookies.
    """

    def __init__(self, db: Database):
        self.db = db

    def record(self, *, method: str, path: str, status: int, duration_ms: float,
               user_id: int | None = None, username: str = "", token_id: str = "",
               ip: str = "", user_agent: str = "") -> None:
        row = {"ts": time.time(), "user_id": user_id, "username": username, "token_id": token_id[:16],
               "ip": ip[:64], "method": method[:10], "path": path[:300], "status": int(status),
               "duration_ms": round(float(duration_ms), 2), "user_agent": user_agent[:300]}
        cur = self.db.execute(
            "INSERT INTO activity (ts, user_id, username, token_id, ip, method, path, status, duration_ms, "
            "user_agent) VALUES (:ts, :user_id, :username, :token_id, :ip, :method, :path, :status, "
            ":duration_ms, :user_agent)", row)
        row["id"] = cur.lastrowid
        LOG.activity(row)

    def purge(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cur = self.db.execute("DELETE FROM activity WHERE ts < ?", (time.time() - retention_days * 86400,))
        return cur.rowcount or 0

    def query(self, *, user_id: int | None = None, username: str = "", outcome: str = "",
              q: str = "", since: float | None = None, until: float | None = None,
              limit: int = 200, before_id: int | None = None, path: str = "", method: str = "",
              token_id: str = "", **_ignored: Any) -> list[dict]:
        where, params = [], []
        if user_id is not None:
            where.append("user_id = ?"); params.append(user_id)
        if username:
            where.append("username LIKE ?"); params.append(f"%{username}%")
        if outcome in ("ok", "success"):
            where.append("status < 400")
        elif outcome:
            where.append("status >= 400")
        if path:
            where.append("path LIKE ?"); params.append(f"%{path}%")
        if method:
            where.append("method = ?"); params.append(method.upper())
        if token_id:
            where.append("token_id = ?"); params.append(token_id)
        if q:
            where.append("(path LIKE ? OR ip LIKE ? OR username LIKE ? OR token_id LIKE ?)")
            params += [f"%{q}%"] * 4
        if since is not None:
            where.append("ts >= ?"); params.append(since)
        if until is not None:
            where.append("ts < ?"); params.append(until)
        if before_id is not None:
            where.append("id < ?"); params.append(before_id)
        sql = "SELECT * FROM activity" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        return self.db.all(sql, tuple(params))
