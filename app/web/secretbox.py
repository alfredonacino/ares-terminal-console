"""APP_KEY and the sealed values derived from it (stored credentials)."""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def app_key(data_dir: Path, create: bool = True) -> bytes:
    """The install's APP_KEY: the environment's (pm2 .env, k8s Secret), else DATA_DIR/.app_key."""
    env = os.environ.get("APP_KEY", "").strip()
    if env:
        return env.encode()
    path = Path(data_dir) / ".app_key"
    if not path.exists():
        if not create:
            return b""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32))
    return path.read_text().strip().encode()


def derive(app_key_: bytes, salt: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=salt, info=b"v1").derive(app_key_)


class Sealer:
    """``v1:`` + base64(nonce | AES-256-GCM) under a key derived from APP_KEY."""

    def __init__(self, app_key_: bytes, salt: bytes, aad: bytes):
        self._k = derive(app_key_, salt)
        self._aad = aad

    def seal(self, value: str) -> str:
        nonce = os.urandom(12)
        return "v1:" + base64.b64encode(nonce + AESGCM(self._k).encrypt(nonce, value.encode(), self._aad)).decode()

    def open(self, blob: str) -> str:
        if not blob:
            return ""
        raw = base64.b64decode(blob.split(":", 1)[1])
        return AESGCM(self._k).decrypt(raw[:12], raw[12:], self._aad).decode()


# One salt per purpose. backup.rekey() re-encrypts every one of these on a restore.
SALTS = {
    "backup": (b"ares-terminal-console-backup", b"backup"),
    "log-forwarding": (b"ares-terminal-console-log-forwarding", b"log-forwarding"),
    "sso": (b"ares-terminal-console-sso", b"sso"),
    "mfa": (b"ares-terminal-console-mfa", b"mfa"),
}


def sealer(app_key_: bytes, purpose: str) -> Sealer:
    salt, aad = SALTS[purpose]
    return Sealer(app_key_, salt, aad)
