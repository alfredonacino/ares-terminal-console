"""Web mode: users, sign-in (password + TOTP, Entra ID / OIDC, SAML 2.0, LDAP), API tokens,
audit and activity, JSON logs with SIEM forwarding, and backup and restore.

Everything here is optional at import time for the terminal itself: ``app.server`` imports
this package lazily, so a bare ``./run.sh`` on the standard library alone still opens a shell.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def _manifest() -> dict:
    try:
        return json.loads((ROOT / "ares.app.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _version() -> str:
    try:
        v = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        if re.fullmatch(r"\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?", v):
            return v
    except OSError:
        pass
    return "0.0.0"


_M = _manifest()
KEY = _M.get("key") if re.fullmatch(r"[a-z0-9-]{1,63}", str(_M.get("key") or "")) else "ares-terminal-console"
TOKEN_PREFIX = str((_M.get("api") or {}).get("tokenPrefix") or "ares")
__version__ = _version()
