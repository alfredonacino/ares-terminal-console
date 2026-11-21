"""Time-based one-time passwords (RFC 6238, SHA-1, 6 digits, 30 s) and recovery codes.

Standard library only. Works with every authenticator app (Microsoft Authenticator, Google
Authenticator, 1Password, Authy, FreeOTP, ...).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP = 30
DIGITS = 6
WINDOW = 1            # accept the previous and the next step too (clock drift)
RECOVERY_COUNT = 10
_CODE_RE = re.compile(r"^\d{6}$")
_RECOVERY_RE = re.compile(r"^[a-z0-9]{4}-?[a-z0-9]{4}$")
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"     # no 0/o, 1/l/i


def new_secret() -> str:
    """160 random bits, base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    mac = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    n = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(n).zfill(DIGITS)


def verify(secret: str, code: str, last_step: int = 0, at: float | None = None) -> int:
    """The matched time step (> last_step, so a code works once), or 0 when the code is wrong."""
    code = re.sub(r"\s", "", code or "")
    if not secret or not _CODE_RE.match(code):
        return 0
    now = int((at if at is not None else time.time()) // STEP)
    matched = 0
    for step in range(now - WINDOW, now + WINDOW + 1):
        # Compare every candidate (no early exit) so timing says nothing about which one matched.
        if hmac.compare_digest(code_at(secret, step), code) and step > last_step:
            matched = step
    return matched


def otpauth_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}", safe="@")
    # quote_via=quote: spaces as %20, not '+', which some authenticator apps show literally.
    return f"otpauth://totp/{label}?" + urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP},
        quote_via=quote)


def qr_svg(data: str) -> str:
    """An SVG QR code of ``data`` (segno, pure Python), or '' when segno is not installed."""
    try:
        import io

        import segno
    except ImportError:
        return ""
    buf = io.BytesIO()
    # omitsize: a viewBox instead of a fixed width/height, so the code scales to the box the page
    # gives it instead of being cropped (a cropped code cannot be scanned). border=4 is the quiet
    # zone the QR standard asks for; phone cameras miss codes with less.
    segno.make(data, error="m").save(buf, kind="svg", scale=1, border=4, dark="#000", light="#fff",
                                     xmldecl=False, svgns=True, omitsize=True)
    return buf.getvalue().decode()


# ── recovery codes ──

def new_recovery_codes() -> list[str]:
    out = []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(8))
        out.append(f"{raw[:4]}-{raw[4:]}")
    return out


def hash_recovery(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace("-", "").encode()).hexdigest()


def looks_like_recovery(code: str) -> bool:
    return bool(_RECOVERY_RE.match((code or "").strip().lower()))


def use_recovery(stored: list[str], code: str) -> list[str] | None:
    """The remaining hashes after using ``code``, or None when it is not one of them."""
    h = hash_recovery(code)
    hit = None
    for s in stored:
        if hmac.compare_digest(s, h):
            hit = s
    if hit is None:
        return None
    return [s for s in stored if s != hit]
