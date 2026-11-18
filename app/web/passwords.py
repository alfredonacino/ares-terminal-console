"""Password hashing (scrypt, standard library only) and the password policy."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N, _R, _P, _DKLEN = 2 ** 15, 8, 1, 32
_MAXMEM = 128 * 1024 * 1024
MIN_LENGTH = 12

# Verified against when the username does not exist, so a missing account
# costs the same time as a wrong password and cannot be told apart by timing.
_DUMMY: str = ""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P,
                        dklen=_DKLEN, maxmem=_MAXMEM)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    global _DUMMY
    if not stored:
        if not _DUMMY:
            _DUMMY = hash_password(secrets.token_urlsafe(16))
        stored, password = _DUMMY, password + "\x00"
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt),
                            n=int(n), r=int(r), p=int(p),
                            dklen=len(base64.b64decode(expected)), maxmem=_MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, base64.b64decode(expected)) and stored is not _DUMMY


def policy_error(password: str, username: str = "") -> str:
    """Why this password is not acceptable, or '' when it is."""
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters."
    if len(password) > 256:
        return "Password must be at most 256 characters."
    if username and username.lower() in password.lower():
        return "Password must not contain the username."
    classes = sum(bool(any(f(c) for c in password))
                  for f in (str.islower, str.isupper, str.isdigit,
                            lambda c: not c.isalnum()))
    if classes < 3:
        return "Use at least three of: lowercase, uppercase, digits, symbols."
    return ""


def generate() -> str:
    """A random password that satisfies the policy."""
    while True:
        pw = secrets.token_urlsafe(15) + "-" + str(secrets.randbelow(90) + 10)
        if not policy_error(pw):
            return pw
