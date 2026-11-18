"""Backup and restore (ARES standard §7): one archive that brings ARES Terminal Console back.

    <key>-backup-<YYYYMMDDTHHMMSSZ>.tar.gz[.enc]
      manifest.json         format suite-backup/1, key, version, a sha256 for every file
      db/ares-terminal-console.db   online-backup snapshot of the database
      data/users/<id>/…     each user's history, servers, shell home (~/.ssh) and anything else in DATA_DIR
      secrets/app_key       the APP_KEY that encrypted the stored credentials in that database

Destinations: local (``DATA_DIR/backups``), SSH/SFTP and S3-compatible, each with its own retention.
Encryption is the standard's exact layout (``SUITEBK1`` | salt | nonce | AES-256-GCM), with a key
derived from the backup passphrase by scrypt. The passphrase is stored (encrypted with APP_KEY) so the
schedule can run, but it is removed from every database snapshot, so it is never inside a backup.

Restore verifies first, takes a local safety backup, then *stages* the backup in
``DATA_DIR/.restore-pending``. The swap happens in :func:`apply_pending`, which ``app/main.py`` runs
before the server opens the database (the server restarts itself after staging). A restore keeps
the install's own APP_KEY and re-encrypts the restored credentials to it.

This module never imports the server app: the CLI (``python app/main.py backup …``) must work when
the server cannot start, and on a fresh install with an empty DATA_DIR.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import sys
import tarfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import quote, urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import KEY, __version__
from .secretbox import Sealer, app_key, sealer as _sealer


FORMAT = "suite-backup/1"
MAGIC = b"SUITEBK1"
DB_NAME = "ares-terminal-console.db"
NAME_RE = re.compile(r"^" + re.escape(KEY) + r"-backup-(\d{8}T\d{6}Z)\.tar\.gz(\.enc)?$")
TYPES = ("local", "sftp", "s3")
MODES = ("off", "hourly", "every", "daily", "weekly")
REASONS = ("manual", "scheduled", "pre-restore")
MIN_PASSPHRASE = 12
LEASE_TTL = 600.0

# Never in a backup: earlier backups, runtime (sockets, the tmpfs fallback), the consoles' diagnostic
# logs, tools a deploy reinstalls, restore scratch space, the one-time admin password, and the live
# database files (the snapshot is taken through SQLite's online-backup API instead).
_EXCLUDE_TOP = {"backups", "run", "logs", "bin", "webview", "ssh", "access-token",
                "initial-admin-password.txt", ".app_key",
                DB_NAME, DB_NAME + "-wal", DB_NAME + "-shm", DB_NAME + "-journal"}
_EXCLUDE_USER = {"tmp"}                         # scratch space
_EXCLUDE_SUFFIX = (".sock", ".lock", ".tmp", ".part", ".pid")
# Settings that never leave the install in a snapshot (the passphrase) or are per-install state.
_SCRUB_SETTINGS = ("backup_passphrase", "backup_restored")
_CARRY_SETTINGS = ("backup_passphrase", "backup_state")


class BackupError(Exception):
    pass


# ─── keys and small helpers ──────────────────────────────────────────────────

def backup_sealer(app_key_: bytes) -> Sealer:
    return _sealer(app_key_, "backup")


def forwarding_sealer(app_key_: bytes) -> Sealer:
    return _sealer(app_key_, "log-forwarding")


def _utc_stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def archive_name(ts: float, encrypted: bool) -> str:
    return f"{KEY}-backup-{_utc_stamp(ts)}.tar.gz" + (".enc" if encrypted else "")


def name_time(name: str) -> float | None:
    m = NAME_RE.match(name)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()


def _version_tuple(v: str) -> tuple[int, ...]:
    core = re.split(r"[-+]", str(v or "0"))[0]
    return tuple(int(x) if x.isdigit() else 0 for x in core.split("."))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ─── encryption (standard layout) ────────────────────────────────────────────

def _scrypt(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_scrypt(passphrase, salt)).encrypt(nonce, data, MAGIC)


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    if blob[:8] != MAGIC or len(blob) < 8 + 16 + 12 + 16:
        raise BackupError("This is not an encrypted suite-backup/1 archive.")
    salt, nonce = blob[8:24], blob[24:36]
    try:
        return AESGCM(_scrypt(passphrase, salt)).decrypt(nonce, blob[36:], MAGIC)
    except Exception:
        raise BackupError("Wrong backup passphrase, or the archive is damaged.") from None


def is_encrypted_file(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(8) == MAGIC


# ─── database access without the server ─────────────────────────────────────

class _Settings:
    """settings-table access through the server's Database; with none (a broken database in the
    CLI) every read is the default and writes are dropped."""

    def __init__(self, db=None, path: Path | None = None):
        self.db = db
        self.path = path

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        return c

    def get(self, key: str, default: Any = None) -> Any:
        if self.db is not None:
            return self.db.get_setting(key, default)
        if not self.path or not self.path.exists():
            return default
        with contextlib.closing(self._conn()) as c:
            row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        try:
            return json.loads(row[0]) if row else default
        except ValueError:
            return default

    def set(self, key: str, value: Any) -> None:
        if self.db is not None:
            self.db.set_setting(key, value)
            return
        if not self.path:
            return
        with contextlib.closing(self._conn()) as c:
            c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
                      "value = excluded.value", (key, json.dumps(value)))

    def delete(self, key: str) -> None:
        if self.db is not None:
            self.db.execute("DELETE FROM settings WHERE key = ?", (key,))
            return
        if not self.path:
            return
        with contextlib.closing(self._conn()) as c:
            c.execute("DELETE FROM settings WHERE key = ?", (key,))

    def execute(self, sql: str, params: tuple = ()) -> int:
        if self.db is not None:
            return self.db.execute(sql, params).rowcount or 0
        if not self.path:
            return 1
        with contextlib.closing(self._conn()) as c:
            return c.execute(sql, params).rowcount or 0


# ─── destinations ────────────────────────────────────────────────────────────

class Destination:
    """put / list / get / delete of archives in one place. Only NAME_RE files are ever listed or deleted."""

    def put(self, path: Path, name: str) -> None: ...
    def list(self) -> list[dict]: ...
    def get(self, name: str, to: Path) -> None: ...
    def delete(self, name: str) -> None: ...

    def test(self) -> str:
        self.list()
        return "reachable"

    def close(self) -> None:
        pass

    @staticmethod
    def _check_name(name: str) -> str:
        if not NAME_RE.match(name or ""):
            raise BackupError(f"Not a {KEY} backup name: {name!r}")
        return name


class LocalDest(Destination):
    def __init__(self, root: Path):
        self.root = root

    def put(self, path: Path, name: str) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        tmp = self.root / f".{name}.part"
        shutil.copyfile(path, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.root / self._check_name(name))

    def list(self) -> list[dict]:
        if not self.root.is_dir():
            return []
        out = []
        for p in self.root.iterdir():
            if NAME_RE.match(p.name) and p.is_file():
                st = p.stat()
                out.append({"name": p.name, "size": st.st_size, "modified": st.st_mtime})
        return out

    def path(self, name: str) -> Path:
        p = self.root / self._check_name(name)
        if not p.is_file():
            raise BackupError(f"No backup {name} in the local destination.")
        return p

    def get(self, name: str, to: Path) -> None:
        shutil.copyfile(self.path(name), to)

    def delete(self, name: str) -> None:
        (self.root / self._check_name(name)).unlink(missing_ok=True)

    def test(self) -> str:
        self.root.mkdir(parents=True, exist_ok=True)
        probe = self.root / f".write-test-{secrets.token_hex(4)}"
        probe.write_bytes(b"ok")
        probe.unlink()
        free = shutil.disk_usage(self.root).free
        return f"writable, {free / 2**30:.1f} GiB free"


def _load_pkey(pem: str, passphrase: str | None):
    import paramiko
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise BackupError("The private key is encrypted: enter its passphrase.") from None
        except Exception as e:  # noqa: BLE001 - try the next key type
            errors.append(str(e))
    raise BackupError("The private key could not be read (OpenSSH or PEM Ed25519, ECDSA or RSA).")


def host_key_fingerprint(line: str) -> str:
    try:
        blob = base64.b64decode(line.split()[1])
    except (IndexError, ValueError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


class SftpDest(Destination):
    def __init__(self, cfg: dict, password: str = "", private_key: str = "", key_passphrase: str = "",
                 on_pin: Callable[[str], None] | None = None, timeout: float = 30.0):
        self.cfg = cfg
        self.password, self.private_key, self.key_passphrase = password, private_key, key_passphrase
        self.on_pin = on_pin
        self.timeout = timeout
        self._t = None
        self._sftp = None

    def _client(self):
        if self._sftp is not None:
            return self._sftp
        import paramiko
        host, port = self.cfg["host"], int(self.cfg.get("port") or 22)
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        except OSError as e:
            raise BackupError(f"cannot connect to {host}:{port}: {e}") from None
        t = paramiko.Transport(sock)
        t.banner_timeout = self.timeout
        t.auth_timeout = self.timeout
        try:
            t.start_client(timeout=self.timeout)
            k = t.get_remote_server_key()
            seen = f"{k.get_name()} {k.get_base64()}"
            pinned = self.cfg.get("host_key") or ""
            if pinned and pinned != seen:
                raise BackupError(f"the server's host key changed (now {host_key_fingerprint(seen)}, pinned "
                                  f"{host_key_fingerprint(pinned)}). If that is expected, clear the pinned key "
                                  "on the destination.")
            if not pinned:
                self.cfg["host_key"] = seen
                if self.on_pin:
                    self.on_pin(seen)
            user = self.cfg.get("user") or ""
            if self.private_key:
                t.auth_publickey(user, _load_pkey(self.private_key, self.key_passphrase))
            else:
                t.auth_password(user, self.password)
            if not t.is_authenticated():
                raise BackupError("authentication failed")
            self._t, self._sftp = t, paramiko.SFTPClient.from_transport(t)
        except BackupError:
            t.close()
            raise
        except paramiko.AuthenticationException:
            t.close()
            raise BackupError(f"authentication failed for user {self.cfg.get('user')!r}") from None
        except Exception as e:  # noqa: BLE001
            t.close()
            raise BackupError(f"SFTP: {type(e).__name__}: {e}") from None
        self._sftp.get_channel().settimeout(max(self.timeout, 120.0))
        return self._sftp

    def _dir(self) -> str:
        return (self.cfg.get("directory") or ".").rstrip("/") or "/"

    def _mkdirs(self) -> None:
        s = self._client()
        d = self._dir()
        if d in (".", "/"):
            return
        parts, cur = d.split("/"), ""
        for i, part in enumerate(parts):
            if part == "" and i == 0:
                cur = "/"
                continue
            cur = (cur.rstrip("/") + "/" + part) if cur else part
            try:
                s.stat(cur)
            except FileNotFoundError:
                s.mkdir(cur, 0o700)

    def _p(self, name: str) -> str:
        return f"{self._dir().rstrip('/')}/{name}" if self._dir() != "/" else f"/{name}"

    def put(self, path: Path, name: str) -> None:
        self._check_name(name)
        try:
            self._mkdirs()
            s = self._client()
            tmp = self._p(f".{name}.part")
            s.put(str(path), tmp, confirm=True)
            s.rename(tmp, self._p(name))
        except BackupError:
            raise
        except Exception as e:  # noqa: BLE001
            raise BackupError(f"SFTP upload: {type(e).__name__}: {e}") from None

    def list(self) -> list[dict]:
        s = self._client()
        try:
            entries = s.listdir_attr(self._dir())
        except FileNotFoundError:
            return []
        except Exception as e:  # noqa: BLE001
            raise BackupError(f"SFTP list: {type(e).__name__}: {e}") from None
        return [{"name": a.filename, "size": a.st_size or 0, "modified": a.st_mtime or 0}
                for a in entries if NAME_RE.match(a.filename) and stat.S_ISREG(a.st_mode or 0)]

    def get(self, name: str, to: Path) -> None:
        try:
            self._client().get(self._p(self._check_name(name)), str(to))
        except BackupError:
            raise
        except Exception as e:  # noqa: BLE001
            raise BackupError(f"SFTP download: {type(e).__name__}: {e}") from None

    def delete(self, name: str) -> None:
        self._client().remove(self._p(self._check_name(name)))

    def test(self) -> str:
        self._mkdirs()
        s = self._client()
        probe = self._p(f".write-test-{secrets.token_hex(4)}")
        with s.open(probe, "wb") as f:
            f.write(b"ok")
        s.remove(probe)
        return f"writable; host key {host_key_fingerprint(self.cfg.get('host_key', ''))}"

    def close(self) -> None:
        for x in (self._sftp, self._t):
            with contextlib.suppress(Exception):
                if x is not None:
                    x.close()
        self._sftp = self._t = None


class S3Dest(Destination):
    """S3-compatible object storage with AWS Signature V4 (AWS S3, MinIO, Ceph RGW, Wasabi, …)."""

    def __init__(self, cfg: dict, secret_key: str, timeout: float = 60.0, verify: bool | str = True):
        self.cfg = cfg
        self.secret = secret_key
        self.region = cfg.get("region") or "us-east-1"
        self.bucket = cfg["bucket"]
        self.prefix = cfg.get("prefix") or ""
        ep = (cfg.get("endpoint") or f"https://s3.{self.region}.amazonaws.com").rstrip("/")
        u = urlsplit(ep)
        self.scheme, self.netloc = u.scheme or "https", u.netloc
        self.path_style = bool(cfg.get("path_style"))
        self.timeout = timeout
        self.verify = verify

    def _host_path(self, key: str) -> tuple[str, str]:
        k = quote(key, safe="/-_.~")
        if self.path_style:
            return self.netloc, f"/{quote(self.bucket, safe='-_.~')}" + (f"/{k}" if key else "")
        return f"{self.bucket}.{self.netloc}", f"/{k}"

    def _sign(self, method: str, host: str, path: str, query: dict, payload_hash: str) -> dict:
        now = datetime.now(timezone.utc)
        amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        cq = "&".join(f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted(query.items()))
        headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        signed = ";".join(sorted(headers))
        ch = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
        creq = "\n".join([method, path, cq, ch, signed, payload_hash])
        scope = f"{date}/{self.region}/s3/aws4_request"
        sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
        k = ("AWS4" + self.secret).encode()
        for part in (date, self.region, "s3", "aws4_request"):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        return {"x-amz-content-sha256": payload_hash, "x-amz-date": amz_date,
                "authorization": f"AWS4-HMAC-SHA256 Credential={self.cfg['access_key']}/{scope}, "
                                 f"SignedHeaders={signed}, Signature={sig}"}, cq

    def _request(self, method: str, key: str = "", query: dict | None = None, body=b"",
                 payload_hash: str | None = None, length: int | None = None, stream_to: Path | None = None):
        import httpx
        query = query or {}
        host, path = self._host_path(key)
        ph = payload_hash or hashlib.sha256(body if isinstance(body, bytes) else b"").hexdigest()
        headers, cq = self._sign(method, host, path, query, ph)
        url = f"{self.scheme}://{host}{path}" + (f"?{cq}" if cq else "")
        if length is not None:
            headers["content-length"] = str(length)
        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify) as c:
                req = c.build_request(method, url, headers=headers, content=body)
                r = c.send(req, stream=stream_to is not None)
                try:
                    if r.status_code >= 300:
                        r.read()
                        raise BackupError(f"S3 {method} {r.status_code}: {_s3_error(r.text)}")
                    if stream_to is not None:
                        with open(stream_to, "wb") as f:
                            for chunk in r.iter_bytes(1 << 20):
                                f.write(chunk)
                        return None
                    return r.read()
                finally:
                    r.close()
        except BackupError:
            raise
        except httpx.HTTPError as e:
            raise BackupError(f"S3: {type(e).__name__}: {e}") from None

    def put(self, path: Path, name: str) -> None:
        self._check_name(name)
        size = path.stat().st_size
        ph = _sha256_file(path)
        with open(path, "rb") as f:
            self._request("PUT", self.prefix + name, body=f, payload_hash=ph, length=size)

    def list(self) -> list[dict]:
        out, token = [], None
        while True:
            q = {"list-type": "2", "prefix": self.prefix}
            if token:
                q["continuation-token"] = token
            root = _xml(self._request("GET", "", q))
            for c in _xfind(root, "Contents"):
                name = _xtext(c, "Key")[len(self.prefix):]
                if "/" not in name and NAME_RE.match(name):
                    out.append({"name": name, "size": int(_xtext(c, "Size") or 0),
                                "modified": _s3_time(_xtext(c, "LastModified"))})
            if _xtext(root, "IsTruncated") != "true":
                return out
            token = _xtext(root, "NextContinuationToken")
            if not token:
                return out

    def get(self, name: str, to: Path) -> None:
        self._request("GET", self.prefix + self._check_name(name), stream_to=to)

    def delete(self, name: str) -> None:
        self._request("DELETE", self.prefix + self._check_name(name))

    def test(self) -> str:
        probe = f"{self.prefix}.write-test-{secrets.token_hex(4)}"
        self._request("PUT", probe, body=b"ok", length=2)
        self._request("DELETE", probe)
        n = len(self.list())
        return f"writable; {n} backup(s) in s3://{self.bucket}/{self.prefix}"


def _xml(data: bytes):
    from lxml import etree
    return etree.fromstring(data, etree.XMLParser(resolve_entities=False, no_network=True))


def _xfind(root, tag: str) -> list:
    return [e for e in root if isinstance(e.tag, str) and e.tag.rsplit("}", 1)[-1] == tag]


def _xtext(el, tag: str) -> str:
    found = _xfind(el, tag)
    return (found[0].text or "") if found else ""


def _s3_error(text: str) -> str:
    try:
        root = _xml(text.encode())
        return f"{_xtext(root, 'Code')}: {_xtext(root, 'Message')}".strip(": ") or text[:200]
    except Exception:  # noqa: BLE001
        return text[:200] or "no details"


def _s3_time(s: str) -> float:
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 0.0


# ─── schedule ────────────────────────────────────────────────────────────────

DEFAULT_SCHEDULE = {"mode": "daily", "hours": 6, "time": "02:30", "weekday": 6}


def next_run(sched: dict, after: float) -> float | None:
    """The first scheduled time strictly after ``after`` (server local time), or None when off."""
    mode = sched.get("mode", "off")
    if mode == "off":
        return None
    t = datetime.fromtimestamp(after).replace(second=0, microsecond=0)
    if mode in ("hourly", "every"):
        n = 1 if mode == "hourly" else max(1, min(24, int(sched.get("hours") or 1)))
        c = t.replace(minute=0) + timedelta(hours=1)
        while c.hour % n:
            c += timedelta(hours=1)
        return c.timestamp()
    hh, mm = (int(x) for x in str(sched.get("time") or "02:30").split(":"))
    c = t.replace(hour=hh, minute=mm)
    if c.timestamp() <= after:
        c += timedelta(days=1)
    if mode == "weekly":
        wd = int(sched.get("weekday") or 0) % 7          # 0 = Monday
        while c.weekday() != wd:
            c += timedelta(days=1)
    return c.timestamp()


def validate_schedule(data: dict) -> dict:
    mode = data.get("mode", "off")
    if mode not in MODES:
        raise ValueError("mode must be off, hourly, every, daily or weekly")
    out = {"mode": mode, "hours": DEFAULT_SCHEDULE["hours"], "time": DEFAULT_SCHEDULE["time"],
           "weekday": DEFAULT_SCHEDULE["weekday"]}
    if "hours" in data:
        try:
            out["hours"] = int(data["hours"])
        except (TypeError, ValueError):
            raise ValueError("hours must be a whole number") from None
        if not 1 <= out["hours"] <= 24:
            raise ValueError("hours must be between 1 and 24")
    if "time" in data:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(data["time"])):
            raise ValueError("time must be HH:MM (24-hour)")
        out["time"] = str(data["time"])
    if "weekday" in data:
        try:
            out["weekday"] = int(data["weekday"]) % 7
        except (TypeError, ValueError):
            raise ValueError("weekday must be 0 (Monday) to 6 (Sunday)") from None
    return out


def describe_schedule(s: dict) -> str:
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    return {"off": "off", "hourly": "every hour", "every": f"every {s.get('hours')} hours",
            "daily": f"daily at {s.get('time')}",
            "weekly": f"every {days[int(s.get('weekday', 0)) % 7]} at {s.get('time')}"}.get(s.get("mode"), "off")


def server_timezone() -> str:
    off = time.strftime("%z")
    return f"{time.strftime('%Z')} (UTC{off[:3]}:{off[3:]})"


# ─── destination configuration ───────────────────────────────────────────────

_SECRET_FIELDS = {"sftp": ("password", "private_key", "key_passphrase"), "s3": ("secret_key",)}
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-_:\[\]]{1,255}$")


def default_config() -> dict:
    return {"schedule": dict(DEFAULT_SCHEDULE),
            "destinations": [{"id": "local", "name": "Local (DATA_DIR/backups)", "type": "local",
                              "enabled": True, "retention_days": 14}]}


def validate_destination(data: dict, old: dict | None, sealer: Sealer) -> dict:
    """A destination config from API input. Secrets: omit = keep, "" = remove, value = replace."""
    cfg = dict(old or {})
    typ = (old or {}).get("type") or data.get("type")
    if typ not in TYPES:
        raise ValueError("type must be local, sftp or s3")
    if typ == "local" and not old:
        raise ValueError("There is exactly one local destination; edit it instead.")
    cfg["type"] = typ
    cfg.setdefault("id", secrets.token_hex(4))
    if "name" in data or not old:
        name = str(data.get("name") or "").strip()[:80]
        if not name:
            raise ValueError("name is required")
        cfg["name"] = name
    if "enabled" in data or not old:
        cfg["enabled"] = bool(data.get("enabled", True))
    if "retention_days" in data or not old:
        try:
            r = int(data.get("retention_days", 30))
        except (TypeError, ValueError):
            raise ValueError("retention_days must be a whole number") from None
        if not 0 <= r <= 3650:
            raise ValueError("retention_days must be between 0 (keep all) and 3650")
        cfg["retention_days"] = r
    if typ == "sftp":
        for k in ("host", "user", "directory"):
            if k in data or not old:
                cfg[k] = str(data.get(k) or "").strip()
        if "port" in data or not old:
            try:
                cfg["port"] = int(data.get("port") or 22)
            except (TypeError, ValueError):
                raise ValueError("port must be a number") from None
            if not 1 <= cfg["port"] <= 65535:
                raise ValueError("port must be 1-65535")
        if not cfg.get("host") or not _HOST_RE.match(cfg["host"]):
            raise ValueError("host is required (a name or an IP address)")
        if not cfg.get("user"):
            raise ValueError("user is required")
        if not cfg.get("directory"):
            cfg["directory"] = "."
        if "host_key" in data:                    # "" clears the pin (re-pinned on next connect)
            hk = str(data["host_key"] or "").strip()
            if hk and len(hk.split()) < 2:
                raise ValueError("host_key must look like 'ssh-ed25519 AAAA…' (or be empty)")
            cfg["host_key"] = " ".join(hk.split()[:2])
        if old and (cfg.get("host"), cfg.get("port")) != (old.get("host"), old.get("port")):
            cfg["host_key"] = str(data.get("host_key") or "").strip()
    if typ == "s3":
        for k in ("endpoint", "region", "bucket", "prefix", "access_key"):
            if k in data or not old:
                cfg[k] = str(data.get(k) or "").strip()
        if "path_style" in data or not old:
            cfg["path_style"] = bool(data.get("path_style", False))
        if cfg["endpoint"] and not re.fullmatch(r"https?://[A-Za-z0-9.\-_:\[\]]+/?", cfg["endpoint"]):
            raise ValueError("endpoint must be https://host[:port] (no path), or empty for AWS S3")
        cfg["endpoint"] = cfg["endpoint"].rstrip("/")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", cfg.get("bucket") or ""):
            raise ValueError("bucket must be a valid S3 bucket name")
        if cfg["region"] and not re.fullmatch(r"[a-z0-9-]{2,40}", cfg["region"]):
            raise ValueError("region looks wrong (for example us-east-1)")
        p = cfg.get("prefix", "").strip("/")
        if p and not re.fullmatch(r"[A-Za-z0-9!_.*'()/\-]{1,200}", p):
            raise ValueError("prefix may use letters, digits and / - _ . ! * ' ( )")
        cfg["prefix"] = p + "/" if p else ""
        if not cfg.get("access_key"):
            raise ValueError("access_key is required")
    for f in _SECRET_FIELDS.get(typ, ()):
        if f in data and data[f] is not None:
            v = str(data[f])
            v = v.strip() + "\n" if f == "private_key" and v.strip() else v
            if v.strip():
                cfg[f + "_enc"] = sealer.seal(v)
            else:
                cfg.pop(f + "_enc", None)
    if typ == "sftp" and not (cfg.get("password_enc") or cfg.get("private_key_enc")):
        raise ValueError("an SFTP destination needs a password or a private key")
    if typ == "s3" and not cfg.get("secret_key_enc"):
        raise ValueError("secret_key is required")
    return cfg


def public_destination(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if not k.endswith("_enc")}
    for f in _SECRET_FIELDS.get(cfg.get("type", ""), ()):
        out[f] = "set" if cfg.get(f + "_enc") else "none"
    if cfg.get("host_key"):
        out["host_key_fingerprint"] = host_key_fingerprint(cfg["host_key"])
    out["requires_encryption"] = cfg.get("type") != "local"
    return out


# ─── the service ─────────────────────────────────────────────────────────────

class Service:
    """Create, list, prune and restore backups for one DATA_DIR. Used by the server and the CLI."""

    def __init__(self, data_dir: Path, *, app_key_: bytes, db=None, version: str = __version__,
                 on_event: Callable[..., None] | None = None,
                 pre_snapshot: Callable[[], Any] | None = None, owner: str = ""):
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / DB_NAME
        self.local_root = self.data_dir / "backups"
        self.app_key = app_key_
        self.sealer = backup_sealer(app_key_)
        self.settings = _Settings(db=db)
        self.version = version
        self.on_event = on_event or (lambda *a, **k: None)
        self.pre_snapshot = pre_snapshot
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(3)}"
        self._lock = threading.Lock()
        self.running: dict | None = None

    # ── configuration ──
    def config(self) -> dict:
        cfg = self.settings.get("backup_config") or default_config()
        if not any(d.get("type") == "local" for d in cfg.get("destinations", [])):
            cfg["destinations"] = default_config()["destinations"] + list(cfg.get("destinations", []))
        cfg.setdefault("schedule", dict(DEFAULT_SCHEDULE))
        return cfg

    def save_config(self, cfg: dict) -> None:
        self.settings.set("backup_config", cfg)

    def destination_cfg(self, did: str) -> dict:
        for d in self.config()["destinations"]:
            if d["id"] == did:
                return d
        raise BackupError("No such destination.")

    def passphrase(self) -> str:
        blob = self.settings.get("backup_passphrase") or ""
        try:
            return self.sealer.open(blob) if blob else ""
        except Exception:  # noqa: BLE001 - APP_KEY changed under it
            return ""

    def set_passphrase(self, value: str) -> None:
        if value:
            if len(value) < MIN_PASSPHRASE:
                raise ValueError(f"The backup passphrase needs at least {MIN_PASSPHRASE} characters.")
            self.settings.set("backup_passphrase", self.sealer.seal(value))
        else:
            self.settings.delete("backup_passphrase")

    def state(self) -> dict:
        return self.settings.get("backup_state") or {}

    def _save_state(self, **kw) -> None:
        st = self.state()
        st.update(kw)
        self.settings.set("backup_state", st)

    def open_destination(self, cfg: dict) -> Destination:
        typ = cfg.get("type")
        if typ == "local":
            return LocalDest(self.local_root)
        try:
            sec = {f: self.sealer.open(cfg.get(f + "_enc", "")) for f in _SECRET_FIELDS[typ]}
        except Exception:  # noqa: BLE001
            raise BackupError("Its stored credentials cannot be decrypted (APP_KEY changed): enter them again.") \
                from None
        if typ == "sftp":
            def pin(line: str, did=cfg["id"]) -> None:
                c = self.config()
                for d in c["destinations"]:
                    if d["id"] == did and not d.get("host_key"):
                        d["host_key"] = line
                self.save_config(c)
                self.on_event("Backup destination host key pinned", target=f"destination={cfg['name']}",
                              detail={"fingerprint": host_key_fingerprint(line)})
            return SftpDest(cfg, sec["password"], sec["private_key"], sec["key_passphrase"], on_pin=pin)
        if typ == "s3":
            return S3Dest(cfg, sec["secret_key"])
        raise BackupError(f"unknown destination type {typ!r}")

    @contextlib.contextmanager
    def _dest(self, cfg: dict) -> Iterator[Destination]:
        d = self.open_destination(cfg)
        try:
            yield d
        finally:
            d.close()

    # ── lease: one replica / process runs a backup at a time ──
    def _lease(self, ttl: float = LEASE_TTL) -> bool:
        t = time.time()
        self.settings.execute("CREATE TABLE IF NOT EXISTS leases (name TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                              "expires_at REAL NOT NULL)")
        self.settings.execute("INSERT OR IGNORE INTO leases (name, owner, expires_at) VALUES ('backup', '', 0)")
        n = self.settings.execute("UPDATE leases SET owner = ?, expires_at = ? WHERE name = 'backup' AND "
                                  "(expires_at < ? OR owner = ?)", (self.owner, t + ttl, t, self.owner))
        return n == 1

    def _release(self) -> None:
        self.settings.execute("UPDATE leases SET expires_at = 0 WHERE name = 'backup' AND owner = ?",
                              (self.owner,))

    # ── create ──
    def _data_files(self) -> list[tuple[Path, str]]:
        out = []
        root = self.data_dir
        if not root.is_dir():
            return out
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = Path(dirpath).relative_to(root)
            parts = rel_dir.parts
            if not parts:
                dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_TOP and not d.startswith(".restore")]
            elif parts[0] == "users" and len(parts) == 2:
                dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_USER]
            dirnames.sort()
            for fn in sorted(filenames):
                if not parts and (fn in _EXCLUDE_TOP or fn.startswith(".restore")):
                    continue
                if fn.endswith(_EXCLUDE_SUFFIX):
                    continue
                p = Path(dirpath) / fn
                try:
                    if not stat.S_ISREG(os.lstat(p).st_mode):
                        continue
                except OSError:
                    continue
                out.append((p, (rel_dir / fn).as_posix()))
        return out

    def _snapshot_db(self, to: Path) -> None:
        to.parent.mkdir(parents=True, exist_ok=True)
        if not self.db_path.exists():
            raise BackupError(f"no database at {self.db_path.name}")
        with contextlib.closing(sqlite3.connect(str(self.db_path), timeout=30)) as src, \
                contextlib.closing(sqlite3.connect(str(to))) as dst:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")
            for k in _SCRUB_SETTINGS:
                with contextlib.suppress(sqlite3.OperationalError):
                    dst.execute("DELETE FROM settings WHERE key = ?", (k,))
            with contextlib.suppress(sqlite3.OperationalError):
                dst.execute("DELETE FROM leases")
            dst.commit()
            dst.execute("VACUUM")
        os.chmod(to, 0o600)

    def _build(self, work: Path, reason: str, encrypt_with: str) -> tuple[Path, dict]:
        """Snapshot + copy into ``work``, write the archive. Returns (archive path, manifest)."""
        stage = work / "stage"
        self._snapshot_db(stage / "db" / DB_NAME)
        files: list[tuple[Path, str]] = [(stage / "db" / DB_NAME, f"db/{DB_NAME}")]
        for src, rel in self._data_files():
            dst = stage / "data" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(src, dst)
            except FileNotFoundError:          # removed while we walked (a user deleted)
                continue
            files.append((dst, f"data/{rel}"))
        key_file = stage / "secrets" / "app_key"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(self.app_key)
        files.append((key_file, "secrets/app_key"))
        t = time.time()
        manifest = {"format": FORMAT, "key": KEY, "version": self.version, "createdAt": _iso(t),
                    "encrypted": bool(encrypt_with), "reason": reason,
                    "files": [{"path": rel, "size": p.stat().st_size, "sha256": _sha256_file(p)}
                              for p, rel in files]}
        tgz = work / "archive.tar.gz"
        with tarfile.open(tgz, "w:gz", compresslevel=6) as tar:
            raw = json.dumps(manifest, indent=2).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size, ti.mtime, ti.mode = len(raw), int(t), 0o600
            tar.addfile(ti, io.BytesIO(raw))
            for p, rel in files:
                ti = tar.gettarinfo(str(p), arcname=rel)
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mode = 0o600
                with open(p, "rb") as f:
                    tar.addfile(ti, f)
        out = tgz
        if encrypt_with:
            out = work / "archive.tar.gz.enc"
            out.write_bytes(encrypt_bytes(tgz.read_bytes(), encrypt_with))
            tgz.unlink()
        shutil.rmtree(stage, ignore_errors=True)
        manifest["_ts"] = t
        return out, manifest

    def create(self, reason: str = "manual", only: list[str] | None = None, actor: dict | None = None) -> dict:
        """One backup to every enabled destination (or ``only`` those ids), then prune each."""
        if reason not in REASONS:
            raise ValueError("bad reason")
        if not self._lock.acquire(blocking=False):
            raise BackupError("A backup is already running.")
        try:
            if not self._lease():
                raise BackupError("A backup is already running in another process.")
            self.running = {"started_at": time.time(), "reason": reason}
            return self._create(reason, only, actor or {})
        finally:
            self.running = None
            with contextlib.suppress(Exception):
                self._release()
            self._lock.release()

    def _create(self, reason: str, only: list[str] | None, actor: dict) -> dict:
        cfg = self.config()
        dests = [d for d in cfg["destinations"] if (d["id"] in only if only else d.get("enabled", True))]
        if not dests:
            raise BackupError("No enabled destination.")
        passphrase = self.passphrase()
        if self.pre_snapshot:
            with contextlib.suppress(Exception):
                self.pre_snapshot()
        self.local_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.local_root, 0o700)
        work = self.local_root / f".work-{secrets.token_hex(4)}"
        work.mkdir(mode=0o700)
        started = time.time()
        results, name, size, error = [], "", 0, ""
        try:
            try:
                archive, manifest = self._build(work, reason, passphrase)
            except Exception as e:  # noqa: BLE001
                error = f"{type(e).__name__}: {e}" if not isinstance(e, BackupError) else str(e)
                raise BackupError(f"Backup could not be built: {error}") from None
            name = archive_name(manifest["_ts"], bool(passphrase))
            while any(name == x["name"] for x in LocalDest(self.local_root).list()):
                time.sleep(1.0)                   # names are unique to the second
                name = archive_name(time.time(), bool(passphrase))
            size = archive.stat().st_size
            for d in dests:
                r = {"id": d["id"], "name": d["name"], "type": d["type"], "ok": False, "error": "",
                     "pruned": []}
                try:
                    if d["type"] != "local" and not passphrase:
                        raise BackupError("a backup passphrase is required for SFTP and S3 destinations "
                                          "(set it on the Backup & Restore page)")
                    with self._dest(d) as dest:
                        dest.put(archive, name)
                        r["ok"] = True
                        r["pruned"] = self._prune(dest, d)
                except Exception as e:  # noqa: BLE001
                    r["error"] = str(e) if isinstance(e, BackupError) else f"{type(e).__name__}: {e}"
                results.append(r)
        except BackupError as e:
            error = str(e)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        ok = bool(results) and all(r["ok"] for r in results) and not error
        summary = {"name": name, "at": started, "duration_s": round(time.time() - started, 1), "size": size,
                   "reason": reason, "encrypted": bool(passphrase), "ok": ok, "error": error,
                   "results": results, "by": actor.get("username", "") if actor else ""}
        hist = [summary] + [h for h in self.state().get("history", []) if h.get("name") != name][:19]
        self._save_state(last=summary, history=hist,
                         **({"last_ok_at": started} if ok else {}),
                         **({"last_scheduled_at": started} if reason == "scheduled" else {}))
        failed = [f"{r['name']}: {r['error']}" for r in results if not r["ok"]]
        self.on_event("Backup created" if ok else "Backup failed", outcome="ok" if ok else "error",
                      target=f"backup={name}" if name else "", actor=actor,
                      detail={"reason": reason, "size": size, "encrypted": bool(passphrase),
                              "destinations": [r["name"] for r in results if r["ok"]],
                              **({"errors": failed} if failed else {}), **({"error": error} if error else {}),
                              **({"pruned": sum(len(r["pruned"]) for r in results)} if any(r["pruned"] for r in results) else {})})
        return summary

    # ── retention ──
    @staticmethod
    def prune_plan(items: list[dict], days: int, now: float) -> list[str]:
        """Names older than ``days``; never the newest; only <key>-backup-* names. 0 days = keep all."""
        dated = sorted(((name_time(i["name"]), i["name"]) for i in items if name_time(i["name"])), reverse=True)
        if days <= 0 or len(dated) <= 1:
            return []
        cutoff = now - days * 86400
        return [n for t, n in dated[1:] if t < cutoff]

    def _prune(self, dest: Destination, cfg: dict) -> list[str]:
        gone = []
        for n in self.prune_plan(dest.list(), int(cfg.get("retention_days", 0)), time.time()):
            dest.delete(n)
            gone.append(n)
        return gone

    def prune(self, actor: dict | None = None) -> list[dict]:
        out = []
        for d in self.config()["destinations"]:
            if not d.get("enabled", True):
                continue
            r = {"id": d["id"], "name": d["name"], "pruned": [], "error": ""}
            try:
                with self._dest(d) as dest:
                    r["pruned"] = self._prune(dest, d)
            except Exception as e:  # noqa: BLE001
                r["error"] = str(e)
            out.append(r)
        if any(r["pruned"] for r in out) or any(r["error"] for r in out):
            self.on_event("Backups pruned", actor=actor, outcome="error" if any(r["error"] for r in out) else "ok",
                          detail={r["name"]: (r["error"] or len(r["pruned"])) for r in out})
        return out

    # ── listing ──
    def list(self, did: str) -> list[dict]:
        with self._dest(self.destination_cfg(did)) as dest:
            items = dest.list()
        for i in items:
            i["created_at"] = name_time(i["name"])
            i["encrypted"] = i["name"].endswith(".enc")
        return sorted(items, key=lambda i: i["created_at"] or 0, reverse=True)

    def fetch(self, did: str, name: str, to: Path) -> None:
        with self._dest(self.destination_cfg(did)) as dest:
            dest.get(name, to)

    # ── schedule ──
    def due(self, now: float | None = None) -> bool:
        now = now or time.time()
        sched = self.config()["schedule"]
        st = self.state()
        last = st.get("last_scheduled_at") or st.get("schedule_since")
        if not last:
            self._save_state(schedule_since=now)
            return False
        nxt = next_run(sched, last)
        return nxt is not None and now >= nxt

    def next_run_at(self) -> float | None:
        st = self.state()
        return next_run(self.config()["schedule"], st.get("last_scheduled_at") or st.get("schedule_since") or time.time())

    def run_if_due(self) -> dict | None:
        if self.running or not self.due():
            return None
        try:
            return self.create("scheduled")
        except BackupError as e:
            self._save_state(last_scheduled_at=time.time())
            self.on_event("Backup failed", outcome="error", detail={"reason": "scheduled", "error": str(e)})
            return None

    # ── restore ──
    def verify(self, archive: Path, passphrase: str, into: Path) -> dict:
        """Decrypt, read the manifest, extract into ``into`` and check every file. Returns the manifest."""
        return verify_archive(archive, passphrase, into, self.version)

    def restore(self, archive: Path, passphrase: str = "", actor: dict | None = None,
                source: str = "", safety: bool = True) -> dict:
        """Verify, take a local safety backup, stage. The caller restarts (server) or applies (CLI)."""
        if not self._lock.acquire(blocking=False):
            raise BackupError("A backup is running; try again when it has finished.")
        pending = self.data_dir / ".restore-pending"
        staging = self.data_dir / f".restore-staging-{secrets.token_hex(4)}"
        try:
            encrypted = is_encrypted_file(archive)
            pw = passphrase or (self.passphrase() if encrypted else "")
            if encrypted and not pw:
                raise BackupError("This backup is encrypted: enter its passphrase.")
            staging.mkdir(mode=0o700)
            manifest = self.verify(archive, pw, staging)
        except BackupError as e:
            shutil.rmtree(staging, ignore_errors=True)
            self.on_event("Backup restore failed", outcome="fail", actor=actor, target=f"backup={source}",
                          detail={"error": str(e), "stage": "verify"})
            self._lock.release()
            raise
        except Exception as e:  # noqa: BLE001
            shutil.rmtree(staging, ignore_errors=True)
            self._lock.release()
            raise BackupError(f"{type(e).__name__}: {e}") from None
        self._lock.release()
        try:
            if safety and self.db_path.exists():     # a fresh install without a database has nothing to keep
                safety = self.create("pre-restore", only=["local"], actor=actor)
                if not safety["ok"]:
                    raise BackupError("The safety backup of the current state failed: "
                                      + (safety["error"] or "; ".join(r["error"] for r in safety["results"])))
            else:
                safety = {"name": ""}
        except BackupError as e:
            shutil.rmtree(staging, ignore_errors=True)
            self.on_event("Backup restore failed", outcome="error", actor=actor, target=f"backup={source}",
                          detail={"error": str(e), "stage": "safety backup"})
            raise
        carry = {"passphrase_enc": self.sealer.seal(pw) if pw and not self.passphrase() else "",
                 "source": source, "safety_backup": safety["name"],
                 "by": (actor or {}).get("username", ""), "staged_at": time.time()}
        (staging / "carry.json").write_text(json.dumps(carry))
        shutil.rmtree(pending, ignore_errors=True)
        os.replace(staging, pending)
        summary = {"name": source, "createdAt": manifest["createdAt"], "version": manifest["version"],
                   "reason": manifest.get("reason", ""), "files": len(manifest["files"]),
                   "safety_backup": safety["name"]}
        self.on_event("Backup restore started", actor=actor, target=f"backup={source}", detail=summary)
        return summary


def verify_archive(archive: Path, passphrase: str, into: Path, running_version: str = __version__) -> dict:
    """Decrypt (if needed), check format/key/version, extract safely into ``into``, verify checksums."""
    work = archive
    tmp: Path | None = None
    try:
        if is_encrypted_file(archive):
            if not passphrase:
                raise BackupError("This backup is encrypted: enter its passphrase.")
            tmp = into / ".decrypted.tar.gz"
            tmp.write_bytes(decrypt_bytes(archive.read_bytes(), passphrase))
            work = tmp
        try:
            tar = tarfile.open(work, "r:gz")
        except (tarfile.TarError, OSError) as e:
            raise BackupError(f"Not a readable .tar.gz backup ({e}).") from None
        with tar:
            first = tar.next()
            if first is None or first.name != "manifest.json" or not first.isfile() or first.size > 50 << 20:
                raise BackupError("manifest.json is not the first file: not a suite-backup/1 archive.")
            try:
                manifest = json.loads(tar.extractfile(first).read())
            except ValueError:
                raise BackupError("manifest.json is not valid JSON.") from None
            if manifest.get("format") != FORMAT:
                raise BackupError(f"Unsupported backup format {manifest.get('format')!r} (expected {FORMAT}).")
            if manifest.get("key") != KEY:
                raise BackupError(f"This backup belongs to {manifest.get('key')!r}, not {KEY}.")
            if _version_tuple(manifest.get("version", "")) > _version_tuple(running_version):
                raise BackupError(f"This backup was written by version {manifest.get('version')}, newer than "
                                  f"the running {running_version}. Install that version or newer first.")
            expected = {f["path"]: f for f in manifest.get("files", [])}
            if f"db/{DB_NAME}" not in expected:
                raise BackupError("The backup has no database snapshot.")
            seen: set[str] = set()
            while (m := tar.next()) is not None:
                rel = m.name
                p = Path(rel)
                if (p.is_absolute() or ".." in p.parts or not rel or rel not in expected
                        or not p.parts[0] in ("db", "data", "secrets") or not m.isfile()):
                    raise BackupError(f"Unexpected entry in the archive: {rel!r}")
                dst = into / p
                dst.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256()
                n = 0
                with tar.extractfile(m) as src, open(dst, "wb") as out:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        h.update(chunk)
                        n += len(chunk)
                        out.write(chunk)
                os.chmod(dst, 0o600)
                f = expected[rel]
                if n != int(f.get("size", -1)) or h.hexdigest() != f.get("sha256"):
                    raise BackupError(f"Checksum mismatch for {rel}: the archive is damaged.")
                seen.add(rel)
            missing = set(expected) - seen
            if missing:
                raise BackupError(f"{len(missing)} file(s) listed in the manifest are missing, e.g. "
                                  f"{sorted(missing)[0]}.")
        (into / "manifest.json").write_text(json.dumps(manifest))
        return manifest
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


# ─── applying a staged restore (before the server opens the database) ───────

def _read_setting_raw(db_path: Path, key: str) -> str | None:
    if not db_path.exists():
        return None
    try:
        with contextlib.closing(sqlite3.connect(str(db_path), timeout=30)) as c:
            row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row[0] if row else None
    except sqlite3.Error:
        return None


def rekey(conn: sqlite3.Connection, old_key: bytes, new_key: bytes) -> dict:
    """Re-encrypt the stored credentials of a restored database from the backup's APP_KEY to ours."""
    counts = {"log_forwarding": 0, "backup_destinations": 0, "sso": 0, "mfa": 0, "dropped": 0}
    if not old_key or old_key == new_key:
        return counts

    def load(key: str):
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def store(key: str, value) -> None:
        conn.execute("UPDATE settings SET value = ? WHERE key = ?", (json.dumps(value), key))

    so, sn = _sealer(old_key, "sso"), _sealer(new_key, "sso")
    for key, field in (("oidc", "client_secret_enc"), ("ldap", "bind_password_enc")):
        cfg = load(key)
        if isinstance(cfg, dict) and cfg.get(field):
            try:
                cfg[field] = sn.seal(so.open(cfg[field]))
                counts["sso"] += 1
            except Exception:  # noqa: BLE001
                cfg[field] = ""
                counts["dropped"] += 1
            store(key, cfg)
    mo, mn = _sealer(old_key, "mfa"), _sealer(new_key, "mfa")
    with contextlib.suppress(sqlite3.OperationalError):
        for uid, blob in conn.execute("SELECT id, totp_secret_enc FROM users WHERE totp_secret_enc != ''").fetchall():
            try:
                conn.execute("UPDATE users SET totp_secret_enc = ? WHERE id = ?", (mn.seal(mo.open(blob)), uid))
                counts["mfa"] += 1
            except Exception:  # noqa: BLE001 - the user enrols again
                conn.execute("UPDATE users SET totp_secret_enc = '', totp_enabled = 0 WHERE id = ?", (uid,))
                counts["dropped"] += 1
    fo, fn = forwarding_sealer(old_key), forwarding_sealer(new_key)
    dests = load("log_forwarding")
    if isinstance(dests, list):
        for d in dests:
            if d.get("auth_enc"):
                try:
                    d["auth_enc"] = fn.seal(fo.open(d["auth_enc"]))
                    counts["log_forwarding"] += 1
                except Exception:  # noqa: BLE001
                    d.pop("auth_enc", None)
                    counts["dropped"] += 1
        store("log_forwarding", dests)
    bo, bn = backup_sealer(old_key), backup_sealer(new_key)
    cfg = load("backup_config")
    if isinstance(cfg, dict):
        for d in cfg.get("destinations", []):
            for k in [k for k in d if k.endswith("_enc")]:
                try:
                    d[k] = bn.seal(bo.open(d[k]))
                    counts["backup_destinations"] += 1
                except Exception:  # noqa: BLE001
                    d.pop(k, None)
                    counts["dropped"] += 1
        store("backup_config", cfg)
    return counts


def apply_pending(data_dir: Path, log: Callable[[str], None] | None = None) -> dict | None:
    """Swap a staged restore into DATA_DIR. Runs before the server opens its database."""
    data_dir = Path(data_dir)
    pending = data_dir / ".restore-pending"
    if not (pending / "manifest.json").is_file():
        if pending.exists():
            shutil.rmtree(pending, ignore_errors=True)
        return None
    log = log or (lambda m: print(m, file=sys.stderr))
    manifest = json.loads((pending / "manifest.json").read_text())
    carry = json.loads((pending / "carry.json").read_text()) if (pending / "carry.json").exists() else {}
    cur_key = app_key(data_dir)
    db_path = data_dir / DB_NAME
    kept = {k: _read_setting_raw(db_path, k) for k in _CARRY_SETTINGS}
    old = data_dir / ".restore-old"
    shutil.rmtree(old, ignore_errors=True)
    old.mkdir(mode=0o700)
    moved: list[tuple[Path, Path]] = []

    def aside(p: Path) -> None:
        if p.exists() or p.is_symlink():
            dst = old / p.relative_to(data_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(p, dst)
            moved.append((dst, p))

    placed: list[Path] = []
    try:
        for n in (DB_NAME, DB_NAME + "-wal", DB_NAME + "-shm", DB_NAME + "-journal"):
            aside(data_dir / n)
        aside(data_dir / "users")
        src_data = pending / "data"
        if src_data.is_dir():
            for entry in sorted(src_data.iterdir()):
                if entry.name in _EXCLUDE_TOP:
                    continue
                target = data_dir / entry.name
                aside(target)
                os.replace(entry, target)
                placed.append(target)
        os.replace(pending / "db" / DB_NAME, db_path)
        placed.append(db_path)
        backup_key = (pending / "secrets" / "app_key").read_bytes().strip() \
            if (pending / "secrets" / "app_key").exists() else b""
        with contextlib.closing(sqlite3.connect(str(db_path), timeout=30, isolation_level=None)) as c:
            c.execute("BEGIN")
            counts = rekey(c, backup_key, cur_key)
            t = time.time()
            with contextlib.suppress(sqlite3.OperationalError):
                c.execute("UPDATE sessions SET ended_at = ?, end_reason = 'restored from backup' "
                          "WHERE ended_at IS NULL", (t,))
            with contextlib.suppress(sqlite3.OperationalError):
                c.execute("DELETE FROM leases")
            for k in _CARRY_SETTINGS:
                c.execute("DELETE FROM settings WHERE key = ?", (k,))
                if kept.get(k) is not None:
                    c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, kept[k]))
            if carry.get("passphrase_enc") and kept.get("backup_passphrase") is None:
                c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_passphrase', ?)",
                          (json.dumps(carry["passphrase_enc"]),))
            notice = {"at": t, "source": carry.get("source", ""), "createdAt": manifest.get("createdAt"),
                      "version": manifest.get("version"), "reason": manifest.get("reason", ""),
                      "files": len(manifest.get("files", [])), "safety_backup": carry.get("safety_backup", ""),
                      "by": carry.get("by", ""), "app_key": "same" if backup_key == cur_key else "re-encrypted",
                      "reencrypted": counts}
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_restored', ?)",
                      (json.dumps(notice),))
            c.execute("COMMIT")
        os.chmod(db_path, 0o600)
    except Exception:
        # Put everything back as it was; leave the staged restore for inspection.
        for p in reversed(placed):
            with contextlib.suppress(OSError):
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
        for src, dst in reversed(moved):
            with contextlib.suppress(OSError):
                os.replace(src, dst)
        failed = data_dir / ".restore-failed"
        shutil.rmtree(failed, ignore_errors=True)
        with contextlib.suppress(OSError):
            os.replace(pending, failed)
        log(f"restore failed and was rolled back; the staged files are in {failed.name}")
        raise
    shutil.rmtree(old, ignore_errors=True)
    shutil.rmtree(pending, ignore_errors=True)
    # The fresh install's one-time admin password belongs to an account the restore just replaced.
    (data_dir / "initial-admin-password.txt").unlink(missing_ok=True)
    log(f"restored the backup from {manifest.get('createdAt')} (version {manifest.get('version')})")
    return notice


def take_restore_notice(db) -> dict | None:
    """The server calls this once at start-up to audit a restore that apply_pending performed."""
    n = db.get_setting("backup_restored")
    if n:
        db.execute("DELETE FROM settings WHERE key = 'backup_restored'")
    return n


# ─── server lock (so the CLI knows whether the server is running) ───────────

_LOCK_FD: int | None = None


def _lock_path(data_dir: Path) -> Path:
    p = Path(data_dir) / "run"
    p.mkdir(parents=True, exist_ok=True)
    return p / "server.lock"


def hold_server_lock(data_dir: Path) -> None:
    global _LOCK_FD
    try:
        import fcntl
    except ImportError:          # Windows: the desktop app has its own single-instance lock
        return
    fd = os.open(_lock_path(data_dir), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return                      # another server on the same DATA_DIR; not our problem here
    _LOCK_FD = fd


def server_running(data_dir: Path) -> bool:
    try:
        import fcntl
    except ImportError:
        return False
    try:
        fd = os.open(_lock_path(data_dir), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


# ─── command line ────────────────────────────────────────────────────────────

def _cli_service(data_dir: Path) -> tuple[Service, bool]:
    db = None
    ok = True
    if (data_dir / DB_NAME).exists():
        try:
            from .db import Database
            db = Database(data_dir / DB_NAME)
        except Exception as e:  # noqa: BLE001 - restore must work when the database is broken
            print(f"warning: the database cannot be opened ({e}); only local backups and files work",
                  file=sys.stderr)
            ok = False
    svc = Service(data_dir, app_key_=app_key(data_dir), db=db,
                  on_event=_cli_audit(db) if db is not None else None)
    return svc, ok


def _cli_audit(db) -> Callable[..., None]:
    def record(action: str, *, outcome: str = "ok", target: str = "", detail: dict | None = None,
               actor: dict | None = None) -> None:
        with contextlib.suppress(Exception):
            db.execute("INSERT INTO audit (ts, username, category, action, target, outcome, detail, user_agent) "
                       "VALUES (?, ?, 'admin', ?, ?, ?, ?, 'backup CLI')",
                       (time.time(), (actor or {}).get("username", "") or f"cli:{getpass.getuser()}",
                        action, target, outcome, json.dumps(detail or {})))
    return record


def _cli_passphrase(args, svc: Service | None, needed: bool) -> str:
    if getattr(args, "passphrase_file", None):
        return Path(args.passphrase_file).read_text().strip("\r\n")
    if os.environ.get("ARES_BACKUP_PASSPHRASE"):
        return os.environ["ARES_BACKUP_PASSPHRASE"]
    stored = svc.passphrase() if svc else ""
    if stored or not needed:
        return stored
    if sys.stdin.isatty():
        return getpass.getpass("Backup passphrase: ")
    raise BackupError("This backup is encrypted: pass --passphrase-file or set ARES_BACKUP_PASSPHRASE.")


def _fmt_size(n: float) -> str:
    for u in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or u == "GiB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return str(n)


def cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python app/main.py backup",
                                 description=f"{KEY} backup and restore (works when the server is stopped).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="one backup to every enabled destination")
    c.add_argument("--destination", "-d", action="append", help="only this destination id (repeatable)")
    lp = sub.add_parser("list", help="backups in every destination")
    lp.add_argument("--destination", "-d", help="only this destination id")
    r = sub.add_parser("restore", help="restore from a file, or a backup name found in a destination")
    r.add_argument("source", help="a path to an archive, or a backup file name")
    r.add_argument("--destination", "-d", help="look for the name in this destination only")
    r.add_argument("--passphrase-file", help="file holding the backup passphrase (or ARES_BACKUP_PASSPHRASE)")
    r.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    r.add_argument("--skip-safety-backup", action="store_true",
                   help="only when the current database is broken and cannot be backed up")
    sub.add_parser("prune", help="apply each destination's retention now")
    args = ap.parse_args(argv)
    data_dir = Path(os.environ.get("DATA_DIR") or "data").resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    svc, db_ok = _cli_service(data_dir)
    try:
        if args.cmd == "create":
            res = svc.create("manual", only=args.destination, actor={"username": f"cli:{getpass.getuser()}"})
            print(f"{res['name']}  {_fmt_size(res['size'])}  {'encrypted' if res['encrypted'] else 'NOT encrypted'}")
            for x in res["results"]:
                print(f"  {'ok ' if x['ok'] else 'ERR'} {x['name']}" + (f": {x['error']}" if x["error"] else "")
                      + (f" (pruned {len(x['pruned'])})" if x["pruned"] else ""))
            if res["error"]:
                print(f"error: {res['error']}", file=sys.stderr)
            return 0 if res["ok"] else 1
        if args.cmd == "list":
            rc = 0
            for d in svc.config()["destinations"]:
                if args.destination and d["id"] != args.destination:
                    continue
                print(f"[{d['id']}] {d['name']} ({d['type']}, keep {d.get('retention_days', 0) or 'all'} days)")
                try:
                    for i in svc.list(d["id"]):
                        print(f"  {i['name']}  {_fmt_size(i['size'])}")
                except Exception as e:  # noqa: BLE001
                    print(f"  error: {e}")
                    rc = 1
            return rc
        if args.cmd == "prune":
            for x in svc.prune(actor={"username": f"cli:{getpass.getuser()}"}):
                print(f"{x['name']}: " + (f"error: {x['error']}" if x["error"] else f"pruned {len(x['pruned'])}"))
            return 0
        if args.cmd == "restore":
            src = Path(args.source)
            tmp = None
            if src.is_file():
                archive, label = src.resolve(), src.name
            else:
                if not NAME_RE.match(args.source):
                    raise BackupError(f"{args.source}: no such file, and not a backup name")
                found = None
                for d in svc.config()["destinations"]:
                    if args.destination and d["id"] != args.destination:
                        continue
                    try:
                        if any(i["name"] == args.source for i in svc.list(d["id"])):
                            found = d
                            break
                    except Exception as e:  # noqa: BLE001
                        print(f"warning: {d['name']}: {e}", file=sys.stderr)
                if not found:
                    raise BackupError(f"{args.source} was not found in any destination")
                svc.local_root.mkdir(parents=True, exist_ok=True)
                tmp = svc.local_root / f".download-{secrets.token_hex(4)}"
                print(f"downloading {args.source} from {found['name']} …")
                svc.fetch(found["id"], args.source, tmp)
                archive, label = tmp, args.source
            try:
                pw = _cli_passphrase(args, svc if db_ok else None, is_encrypted_file(archive))
                running = server_running(data_dir)
                if not args.yes:
                    if not sys.stdin.isatty():
                        raise BackupError("refusing to restore without --yes (not a terminal)")
                    ans = input(f"Replace the current data in {data_dir} with {label}? A safety backup is "
                                "taken first. [y/N] ")
                    if ans.strip().lower() not in ("y", "yes"):
                        print("cancelled")
                        return 1
                info = svc.restore(archive, pw, actor={"username": f"cli:{getpass.getuser()}"}, source=label,
                                   safety=not args.skip_safety_backup)
                print(f"verified {info['files']} files from {info['createdAt']} (version {info['version']}); "
                      f"safety backup: {info['safety_backup'] or 'none'}")
            finally:
                if tmp is not None:
                    tmp.unlink(missing_ok=True)
            if running:
                print("The server is running: the restore is staged and is applied when it restarts "
                      "(pm2 restart, or kubectl rollout restart).")
                return 0
            if svc.settings.db is not None:
                svc.settings.db.close()
            apply_pending(data_dir, log=print)
            return 0
    except (BackupError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
