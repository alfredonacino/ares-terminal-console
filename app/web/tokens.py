"""API tokens (platform standard §8): ``<prefix>_<id>_<secret>``.

* ``<prefix>`` is ``api.tokenPrefix`` from the manifest (``ares``), so secret
  scanners recognise a leaked token.
* ``<id>`` is 8 random hex characters: public, shown in lists and logs, used to
  look the token up.
* ``<secret>`` is 32 bytes from ``secrets`` (CSPRNG), base64url without padding
  (43 characters, 256 bits). Only ``SHA-256(secret)`` is stored, and it is
  compared in constant time. The full token is shown once, at creation.

A token acts as its owner and never exceeds the owner's *current* role: an
``admin`` scope is ignored while the owner is not an administrator, and a
disabled owner disables every token they own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time

from . import TOKEN_PREFIX

SCOPES = ("read", "write", "admin")
DEFAULT_DAYS = 90
MAX_DAYS = 365
FAIL_LIMIT = 20          # failed token uses per source IP ...
FAIL_WINDOW = 15 * 60    # ... in this many seconds, then 429


PREFIX = TOKEN_PREFIX
_ID_RE = re.compile(r"[0-9a-f]{8}")
_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{43}")


class TokenError(Exception):
    def __init__(self, status: int, code: str, message: str, token_id: str = ""):
        super().__init__(message)
        self.status, self.code, self.message, self.token_id = status, code, message, token_id


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def parse(token: str) -> tuple[str, str] | None:
    """(id, secret) of a well-formed token, else None."""
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != PREFIX:
        return None
    tid, secret = parts[1], parts[2]
    if not _ID_RE.fullmatch(tid) or not _SECRET_RE.fullmatch(secret):
        return None
    return tid, secret


def public(row: dict, username: str = "") -> dict:
    """What the UI and API may show about a token (never the hash)."""
    t = time.time()
    state = ("revoked" if row["revoked_at"] else
             "expired" if row["expires_at"] and row["expires_at"] <= t else "active")
    return {"id": row["id"], "name": row["name"], "user_id": row["user_id"],
            "username": username or row.get("username", ""),
            "scopes": row["scopes"].split(","), "created_at": row["created_at"],
            "created_ip": row["created_ip"], "created_by": row["created_by"],
            "expires_at": row["expires_at"], "last_used_at": row["last_used_at"],
            "last_used_ip": row["last_used_ip"], "revoked_at": row["revoked_at"],
            "revoked_by": row["revoked_by"], "state": state}


def normalize_scopes(raw) -> list[str]:
    if isinstance(raw, str):
        raw = [s for s in re.split(r"[\s,]+", raw) if s]
    if not isinstance(raw, list) or not raw:
        raise TokenError(400, "invalid_scopes", "Choose at least one scope: read, write or admin.")
    out = []
    for s in raw:
        s = str(s).strip().lower()
        if s not in SCOPES:
            raise TokenError(400, "invalid_scopes", f"Unknown scope {s!r}; use read, write or admin.")
        if s not in out:
            out.append(s)
    return [s for s in SCOPES if s in out]


def create(db, owner: dict, *, name: str, scopes, expires_days, ip: str,
           created_by: str) -> tuple[str, dict]:
    """Create a token for ``owner``. Returns (full token, row). The token is not stored."""
    name = str(name or "").strip()[:100]
    if not name:
        raise TokenError(400, "invalid_name", "Give the token a name (what will use it).")
    sc = normalize_scopes(scopes)
    if "admin" in sc and owner["role"] != "admin":
        raise TokenError(403, "scope_exceeds_role", "Only administrators can create tokens with the admin scope.")
    if expires_days in (None, "", "never", 0, "0"):
        if expires_days in (None, ""):
            days = DEFAULT_DAYS
        elif owner["role"] != "admin":
            raise TokenError(403, "never_expires", "Only administrators can create tokens that never expire.")
        else:
            days = 0
    else:
        try:
            days = int(expires_days)
        except (TypeError, ValueError):
            raise TokenError(400, "invalid_expiry", "Expiry must be a number of days or \"never\".")
        if not 1 <= days <= MAX_DAYS:
            raise TokenError(400, "invalid_expiry", f"Expiry must be between 1 and {MAX_DAYS} days.")
    t = time.time()
    for _ in range(10):
        tid = secrets.token_hex(4)
        if not db.one("SELECT 1 AS x FROM api_tokens WHERE id = ?", (tid,)):
            break
    else:  # pragma: no cover - 4 billion ids
        raise TokenError(500, "id_collision", "Could not allocate a token id; try again.")
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    db.execute(
        "INSERT INTO api_tokens (id, user_id, name, secret_hash, scopes, created_at, created_ip, "
        "created_by, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (tid, owner["id"], name, _hash(secret), ",".join(sc), t, ip[:64], created_by[:128],
         t + days * 86400 if days else None))
    return f"{PREFIX}_{tid}_{secret}", db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))


def authenticate(db, header: str, ip: str) -> tuple[dict, dict, str]:
    """(token row, owner row, secret) for an ``Authorization: Bearer`` value; raises TokenError."""
    t = time.time()
    n = (db.one("SELECT COUNT(*) AS n FROM login_failures WHERE key = ? AND ts > ?",
                (f"tok:{ip}", t - FAIL_WINDOW)) or {}).get("n", 0)
    if n >= FAIL_LIMIT:
        raise TokenError(429, "rate_limited", "Too many failed token attempts from this address; try again later.")
    scheme, _, value = (header or "").partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise TokenError(401, "missing_token", "Send an API token: Authorization: Bearer <token>.")
    parsed = parse(value.strip())
    if not parsed:
        raise TokenError(401, "invalid_token", "The token is malformed.")
    tid, secret = parsed
    row = db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))
    expected = row["secret_hash"] if row else _hash("x" * 43)
    good = hmac.compare_digest(expected, _hash(secret)) and row is not None
    if not good:
        raise TokenError(401, "invalid_token", "Unknown token or wrong secret.", tid)
    if row["revoked_at"]:
        raise TokenError(401, "revoked_token", "The token has been revoked.", tid)
    if row["expires_at"] and row["expires_at"] <= t:
        raise TokenError(401, "expired_token", "The token has expired.", tid)
    owner = db.one("SELECT * FROM users WHERE id = ?", (row["user_id"],))
    if not owner or owner["disabled"]:
        raise TokenError(401, "owner_disabled", "The token's owner is disabled or deleted.", tid)
    if not row["last_used_at"] or t - row["last_used_at"] > 30 or row["last_used_ip"] != ip:
        db.execute("UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?",
                   (t, ip[:64], tid))
    return row, owner, secret


def effective_scopes(row: dict, owner: dict) -> set[str]:
    sc = set(row["scopes"].split(","))
    if owner["role"] != "admin":
        sc.discard("admin")
    return sc


def record_failure(db, ip: str) -> None:
    db.execute("INSERT INTO login_failures (key, ts) VALUES (?, ?)", (f"tok:{ip}", time.time()))


def revoke(db, tid: str, by: str) -> dict | None:
    row = db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))
    if not row:
        return None
    if not row["revoked_at"]:
        db.execute("UPDATE api_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ?",
                   (time.time(), by[:128], tid))
    return db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))


def rotate(db, tid: str, owner: dict, *, ip: str, by: str) -> tuple[str, dict, dict]:
    """A new token with the same name, scopes and expiry period; the old one is revoked.

    Returns (full new token, new row, old row). Raises TokenError when the old token cannot be rotated.
    """
    old = db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))
    if not old:
        raise TokenError(404, "not_found", "No such token.")
    if old["revoked_at"]:
        raise TokenError(409, "revoked_token", "A revoked token cannot be rotated; create a new one.")
    if old["expires_at"]:
        days = max(1, min(MAX_DAYS, round((old["expires_at"] - old["created_at"]) / 86400)))
    else:
        days = "never"
    scopes = [s for s in old["scopes"].split(",") if s != "admin" or owner["role"] == "admin"]
    full, row = create(db, owner, name=old["name"], scopes=scopes or ["read"], expires_days=days,
                       ip=ip, created_by=by)
    revoke(db, tid, by)
    return full, row, db.one("SELECT * FROM api_tokens WHERE id = ?", (tid,))
