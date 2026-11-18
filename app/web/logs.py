"""JSON logs and forwarding to a log collector / SIEM (platform standard §10).

Every app, audit and activity event becomes one ECS-compatible JSON object:

* on stdout, one per line, when ``LOG_FORMAT=json`` (the default under pm2 and
  in containers; ``text`` is for a developer terminal);
* on every destination configured on the admin **Log forwarding** page, or by
  ``LOG_FORWARD_URL`` in the environment: syslog (RFC 5424 over UDP, TCP or
  TLS, octet-counted) or HTTP(S) POSTs of NDJSON batches.

Delivery never blocks a request. Each destination has its own thread:

* audit and activity are read from the database after a per-destination
  cursor, so they arrive **at least once**, also after an outage or a restart
  (retry with exponential backoff, at most 5 minutes);
* app events go through a bounded in-memory queue (10,000); when it is full
  the oldest are dropped and counted.

Secrets never reach an event: audit details are scrubbed where they are
written, activity rows hold no bodies or headers, and forwarding credentials
are stored encrypted with a key derived from ``APP_KEY``.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import urllib.error
import urllib.request

from . import KEY, __version__
STREAMS = ("audit", "activity", "app")
LEVELS = ("debug", "info", "warn", "error")
APP_QUEUE = 10_000
MAX_BACKOFF = 300.0
FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10,
              **{f"local{i}": 16 + i for i in range(8)}}
_SEVERITY = {"debug": 7, "info": 6, "warn": 4, "error": 3}


def _default_json() -> bool:
    fmt = os.environ.get("LOG_FORMAT", "").strip().lower()
    if fmt in ("json", "text"):
        return fmt == "json"
    # pm2 sets pm_id; Kubernetes sets KUBERNETES_SERVICE_HOST; Docker leaves /.dockerenv.
    return bool(os.environ.get("pm_id") or os.environ.get("KUBERNETES_SERVICE_HOST")
                or Path("/.dockerenv").exists())


def _level(name: str, default: str = "info") -> str:
    n = str(name or "").strip().lower()
    n = {"warning": "warn", "critical": "error", "fatal": "error", "err": "error"}.get(n, n)
    return n if n in LEVELS else default


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int(ts * 1000) % 1000:03d}Z"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")[:80] or "event"


# ─── ECS events ──────────────────────────────────────────────────────────────

_AUDIT_CAT = {"auth": "authentication", "admin": "iam", "console": "web", "terminal": "session",
              "system": "host", "api": "iam", "logging": "configuration"}


def _audit_types(action: str, category: str, outcome: str) -> list[str]:
    a = action.lower()
    if outcome == "denied":
        return ["denied"]
    for words, t in ((("created", "added"), "creation"), (("deleted", "removed", "revoked"), "deletion"),
                     (("changed", "updated", "reset", "saved"), "change"),
                     (("signed in", "opened", "started", "sign-in"), "start"),
                     (("signed out", "closed", "stopped", "exited"), "end")):
        if any(w in a for w in words):
            return ["user", t] if category == "admin" and "user" in a and t in ("creation", "deletion", "change") \
                else [t]
    return ["info"]


def _category(row: dict) -> str:
    a = row.get("action", "").lower()
    if row.get("category") in ("admin", "system") and any(
            w in a for w in ("settings", "policy", "forwarding", "backup")):
        return "configuration"
    return _AUDIT_CAT.get(row.get("category", ""), "host")


class Hub:
    """Formats events, writes them to stdout and feeds the forwarders."""

    def __init__(self) -> None:
        self.key = KEY
        self.version = __version__
        self.environment = os.environ.get("ARES_ENVIRONMENT", "").strip() or "unknown"
        self.host = socket.gethostname()
        self.json = _default_json()
        self.min_level = _level(os.environ.get("LOG_LEVEL", "info"))
        self.db = None
        self._sealer = None
        self._out = threading.Lock()
        self._fwd: dict[str, Forwarder] = {}
        self._fwd_lock = threading.RLock()
        self.file_path: Path | None = None
        self._file = None
        self._file_size = 0

    # ── binding ──
    def bind(self, db, app_key: bytes) -> None:
        self.db = db
        from .secretbox import sealer
        self._sealer = sealer(app_key, "log-forwarding")
        self.reload()

    # ── event construction ──
    def _base(self, ts: float, dataset: str, level: str, message: str) -> dict:
        return {"@timestamp": _iso(ts), "message": message,
                "event": {"kind": "event", "dataset": f"{self.key}.{dataset}"},
                "service": {"name": self.key, "version": self.version, "environment": self.environment},
                "host": {"name": self.host},
                "log": {"level": level, "logger": f"{self.key}.{dataset}"}}

    def app_event(self, level: str, message: str, *, action: str = "", logger: str = "",
                  ts: float | None = None, **labels: Any) -> dict:
        level = _level(level)
        ev = self._base(ts or time.time(), "app", level, str(message)[:4000])
        ev["event"].update({"category": ["process"], "type": ["info"], "action": action or "log"})
        if logger:
            ev["log"]["logger"] = f"{self.key}.app.{logger}"
        if labels:
            ev["labels"] = {k: str(v)[:500] for k, v in labels.items() if v not in (None, "")}
        return ev

    def audit_event(self, row: dict) -> dict:
        outcome = {"ok": "success"}.get(row.get("outcome", "ok"), "failure")
        level = "info" if outcome == "success" else ("error" if row.get("outcome") == "error" else "warn")
        who = row.get("username") or "-"
        target = row.get("target") or ""
        ev = self._base(row["ts"], "audit", level,
                        f"{who}: {row['action']}" + (f" ({target})" if target else ""))
        cat = _category(row)
        ev["event"].update({"category": [cat], "type": _audit_types(row["action"], row.get("category", ""),
                                                                    row.get("outcome", "ok")),
                            "action": slug(row["action"]), "outcome": outcome})
        if row.get("username"):
            ev["user"] = {"name": row["username"]}
            if row.get("user_id") is not None:
                ev["user"]["id"] = str(row["user_id"])
        if row.get("ip"):
            ev["source"] = {"ip": row["ip"]}
        if row.get("user_agent"):
            ev["user_agent"] = {"original": row["user_agent"]}
        if row.get("status"):
            ev["http"] = {"response": {"status_code": int(row["status"])}}
        labels = {"audit_id": str(row["id"]), "category": row.get("category", "")}
        if target:
            labels["object"] = target
        if row.get("token_id"):
            labels["token_id"] = row["token_id"]
        ev["labels"] = labels
        detail = row.get("detail")
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except ValueError:
                detail = {"raw": detail}
        if detail:
            ev["ares"] = {"detail": detail}
        return ev

    def activity_event(self, row: dict) -> dict:
        status = int(row["status"])
        level = "error" if status >= 500 else "warn" if status >= 400 else "info"
        api = row["path"].startswith("/api/v1/")
        ev = self._base(row["ts"], "activity", level, f"{row['method']} {row['path']} {status}")
        ev["event"].update({"category": ["api" if api else "web"], "type": ["access"],
                            "action": "api_call" if api else "http_request",
                            "outcome": "success" if status < 400 else "failure",
                            "duration": int(float(row.get("duration_ms") or 0) * 1_000_000)})
        ev["http"] = {"request": {"method": row["method"]}, "response": {"status_code": status}}
        ev["url"] = {"path": row["path"]}
        if row.get("username"):
            ev["user"] = {"name": row["username"]}
            if row.get("user_id") is not None:
                ev["user"]["id"] = str(row["user_id"])
        if row.get("ip"):
            ev["source"] = {"ip": row["ip"]}
        if row.get("user_agent"):
            ev["user_agent"] = {"original": row["user_agent"]}
        ev["labels"] = {"activity_id": str(row["id"])}
        if row.get("token_id"):
            ev["labels"]["token_id"] = row["token_id"]
        return ev

    # ── output ──
    FILE_MAX = 10 << 20
    FILE_KEEP = 5

    def set_file(self, path: Path) -> None:
        """Also write every event to a rotated JSON-lines file (the desktop: DATA_DIR/logs/<key>.jsonl)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._out:
            self.file_path = path
            self._open_file()

    def _open_file(self) -> None:
        try:
            if self._file:
                self._file.close()
            fd = os.open(self.file_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._file = os.fdopen(fd, "a", encoding="utf-8")
            self._file_size = self.file_path.stat().st_size
        except OSError:
            self._file = None

    def _rotate(self) -> None:
        p = self.file_path
        try:
            self._file.close()
            for i in range(self.FILE_KEEP - 1, 0, -1):
                src = p.with_name(f"{p.name}.{i}")
                if src.exists():
                    os.replace(src, p.with_name(f"{p.name}.{i + 1}"))
            os.replace(p, p.with_name(f"{p.name}.1"))
        except OSError:
            pass
        self._open_file()

    def _stdout(self, ev: dict, stdout: bool = True) -> None:
        line = json.dumps(ev, separators=(",", ":"), default=str, ensure_ascii=False) + "\n"
        with self._out:
            if stdout:
                try:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                except (OSError, ValueError):
                    pass
            if self._file is not None:
                try:
                    self._file.write(line)
                    self._file.flush()
                    self._file_size += len(line)
                    if self._file_size > self.FILE_MAX:
                        self._rotate()
                except (OSError, ValueError):
                    pass

    def app(self, level: str, message: str, *, echo: bool = True, **kw: Any) -> None:
        """An application log line: stdout (JSON or text) and the app stream of each forwarder."""
        level = _level(level)
        if LEVELS.index(level) < LEVELS.index(self.min_level):
            return
        ev = self.app_event(level, message, **kw)
        if echo and self.json:
            self._stdout(ev)
        else:
            if echo:
                with self._out:
                    print(f"[{self.key}] {level}: {message}", file=sys.stderr, flush=True)
            if self._file is not None:
                self._stdout(ev, stdout=False)
        with self._fwd_lock:
            for f in self._fwd.values():
                f.offer_app(ev)

    def audit(self, row: dict) -> None:
        if self.json or self._file is not None:
            self._stdout(self.audit_event(row), stdout=self.json)
        self._wake()

    def activity(self, row: dict) -> None:
        if self.json or self._file is not None:
            self._stdout(self.activity_event(row), stdout=self.json)
        self._wake()

    def _wake(self) -> None:
        with self._fwd_lock:
            for f in self._fwd.values():
                f.wake()

    # ── secrets ──
    def encrypt(self, value: str) -> str:
        return self._sealer.seal(value)

    def decrypt(self, blob: str) -> str:
        return self._sealer.open(blob) if blob else ""

    # ── destinations ──
    def destinations(self) -> list[dict]:
        """Configured destinations (stored), plus the read-only one from the environment."""
        out = list(self.db.get_setting("log_forwarding", []) or [])
        env = env_destination()
        if env:
            out.insert(0, env)
        return out

    def reload(self) -> None:
        """(Re)start one forwarder per enabled destination; stop the others."""
        if self.db is None:
            return
        wanted = {d["id"]: d for d in self.destinations() if d.get("enabled")}
        with self._fwd_lock:
            for did in list(self._fwd):
                f = self._fwd[did]
                if did not in wanted or f.config != wanted[did]:
                    f.stop()
                    del self._fwd[did]
            for did, cfg in wanted.items():
                if did not in self._fwd:
                    f = Forwarder(self, cfg)
                    self._fwd[did] = f
                    f.start()

    def stop_all(self, timeout: float = 5.0) -> None:
        with self._fwd_lock:
            fs = list(self._fwd.values())
            self._fwd.clear()
        for f in fs:
            f.stop(flush_timeout=timeout)

    def status(self) -> dict[str, dict]:
        with self._fwd_lock:
            return {did: f.status() for did, f in self._fwd.items()}

    def init_cursor(self, did: str) -> None:
        """A new destination starts at the current end of the log, not at its beginning."""
        cur = {s: (self.db.one(f"SELECT MAX(id) AS n FROM {s}") or {}).get("n") or 0
               for s in ("audit", "activity")}
        self.db.set_setting(f"logfwd_cursor:{did}", cur)

    def drop_cursor(self, did: str) -> None:
        self.db.execute("DELETE FROM settings WHERE key = ?", (f"logfwd_cursor:{did}",))

    def test(self, cfg: dict, user: str = "") -> str:
        """Send one test event synchronously. Returns '' on success, else the error."""
        ev = self.app_event("info", f"{self.key} log forwarding test event"
                            + (f" sent by {user}" if user else ""), action="test", destination=cfg.get("name", ""))
        sender = make_sender(self, cfg)
        try:
            sender.send([("app", ev)])
            return ""
        except Exception as e:  # noqa: BLE001 - reported to the admin
            return describe_error(e)
        finally:
            sender.close()


LOG = Hub()


def describe_error(e: BaseException) -> str:
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code} from the destination"
    if isinstance(e, urllib.error.URLError):
        return f"cannot reach the destination: {e.reason}"[:300]
    msg = str(e) or type(e).__name__
    return f"{type(e).__name__}: {msg}"[:300]


# ─── Destination configuration ───────────────────────────────────────────────

def env_destination() -> dict | None:
    """LOG_FORWARD_URL (+ _AUTH, _STREAMS, _LEVEL) as a read-only destination."""
    url = os.environ.get("LOG_FORWARD_URL", "").strip()
    if not url:
        return None
    cfg: dict[str, Any] = {"id": "env", "name": "From the environment (LOG_FORWARD_URL)",
                           "enabled": True, "readonly": True,
                           "streams": [s for s in re.split(r"[\s,]+", os.environ.get(
                               "LOG_FORWARD_STREAMS", "audit,activity,app").lower()) if s in STREAMS]
                           or list(STREAMS),
                           "min_level": _level(os.environ.get("LOG_FORWARD_LEVEL", "info"))}
    u = urlsplit(url)
    if u.scheme.startswith("syslog+"):
        cfg.update(type="syslog", transport=u.scheme.split("+", 1)[1], host=u.hostname or "",
                   port=u.port or (6514 if u.scheme.endswith("tls") else 514), facility="local0",
                   verify_tls=True, ca_pem="")
    else:
        cfg.update(type="http", url=url, batch_size=200, timeout=10, verify_tls=True, ca_pem="",
                   auth_env=bool(os.environ.get("LOG_FORWARD_AUTH")))
    return cfg


def validate(data: dict, old: dict | None, hub: Hub) -> dict:
    """Check and normalise a destination from the page. Raises ValueError with a message."""
    old = old or {}
    typ = str(data.get("type", old.get("type", ""))).lower()
    if typ not in ("syslog", "http"):
        raise ValueError("Type must be syslog or http.")
    name = str(data.get("name", old.get("name", ""))).strip()[:100]
    if not name:
        raise ValueError("Give the destination a name.")
    streams = data.get("streams", old.get("streams", list(STREAMS)))
    if isinstance(streams, str):
        streams = re.split(r"[\s,]+", streams)
    streams = [s for s in STREAMS if s in {str(x).lower() for x in streams}]
    if not streams:
        raise ValueError("Choose at least one stream: audit, activity or app.")
    level = str(data.get("min_level", old.get("min_level", "info"))).lower()
    if level not in LEVELS:
        raise ValueError("Minimum level must be debug, info, warn or error.")
    ca = str(data.get("ca_pem", old.get("ca_pem", "")) or "").strip()
    if ca:
        if "-----BEGIN CERTIFICATE-----" not in ca:
            raise ValueError("The CA certificate must be PEM (-----BEGIN CERTIFICATE-----).")
        try:
            ssl.create_default_context(cadata=ca)
        except (ssl.SSLError, ValueError):
            raise ValueError("The CA certificate could not be read.")
    cfg: dict[str, Any] = {"id": old.get("id") or uuid.uuid4().hex[:12], "name": name, "type": typ,
                           "enabled": bool(data.get("enabled", old.get("enabled", True))),
                           "streams": streams, "min_level": level, "ca_pem": ca,
                           "verify_tls": bool(data.get("verify_tls", old.get("verify_tls", True)))}
    if typ == "syslog":
        host = str(data.get("host", old.get("host", ""))).strip()
        if not re.fullmatch(r"[A-Za-z0-9.:\[\]_-]{1,255}", host):
            raise ValueError("Syslog host: a host name or IP address.")
        transport = str(data.get("transport", old.get("transport", "udp"))).lower()
        if transport not in ("udp", "tcp", "tls"):
            raise ValueError("Transport must be udp, tcp or tls.")
        try:
            port = int(data.get("port", old.get("port", 6514 if transport == "tls" else 514)))
        except (TypeError, ValueError):
            raise ValueError("Port must be a number.")
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        facility = str(data.get("facility", old.get("facility", "local0"))).lower()
        if facility not in FACILITIES:
            raise ValueError("Facility must be one of " + ", ".join(FACILITIES) + ".")
        cfg.update(host=host.strip("[]"), port=port, transport=transport, facility=facility)
    else:
        url = str(data.get("url", old.get("url", ""))).strip()
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("URL must be http:// or https://host/path.")
        if u.username or u.password:
            raise ValueError("Put credentials in the auth header, not in the URL.")
        try:
            batch = int(data.get("batch_size", old.get("batch_size", 200)))
            timeout = int(data.get("timeout", old.get("timeout", 10)))
        except (TypeError, ValueError):
            raise ValueError("Batch size and timeout must be numbers.")
        if not 1 <= batch <= 5000:
            raise ValueError("Batch size must be between 1 and 5000.")
        if not 1 <= timeout <= 120:
            raise ValueError("Timeout must be between 1 and 120 seconds.")
        cfg.update(url=url, batch_size=batch, timeout=timeout)
        if "auth_header" in data and data["auth_header"] is not None:
            header = str(data["auth_header"]).strip()
            if header:
                parse_header(header)   # raises ValueError
                cfg["auth_enc"] = hub.encrypt(header)
            # empty string = remove the header
        elif old.get("auth_enc"):
            cfg["auth_enc"] = old["auth_enc"]
    return cfg


def parse_header(raw: str) -> tuple[str, str]:
    """'Authorization: Splunk abc' -> (name, value). A bare value means Authorization."""
    raw = raw.strip()
    m = re.fullmatch(r"([A-Za-z0-9-]{1,64}):\s*(.+)", raw, re.S)
    name, value = (m.group(1), m.group(2).strip()) if m else ("Authorization", raw)
    if not value or "\n" in value or "\r" in value or len(value) > 4096:
        raise ValueError("The auth header must be one line, such as 'Authorization: Splunk <token>'.")
    return name, value


def public_destination(cfg: dict, status: dict | None) -> dict:
    """A destination as the page shows it: never the auth header."""
    out = {k: v for k, v in cfg.items() if k != "auth_enc"}
    out["auth_set"] = bool(cfg.get("auth_enc") or cfg.get("auth_env"))
    out.pop("auth_env", None)
    out["status"] = status or {}
    return out


# ─── Senders ─────────────────────────────────────────────────────────────────

def _ssl_context(cfg: dict) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=cfg["ca_pem"]) if cfg.get("ca_pem") else ssl.create_default_context()
    if not cfg.get("verify_tls", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _line(ev: dict) -> bytes:
    return json.dumps(ev, separators=(",", ":"), default=str, ensure_ascii=False).encode()


class SyslogSender:
    def __init__(self, hub: Hub, cfg: dict):
        self.hub, self.cfg = hub, cfg
        self.sock: socket.socket | None = None
        self.pid = str(os.getpid())

    def frame(self, stream: str, ev: dict) -> bytes:
        sev = _SEVERITY.get(ev.get("log", {}).get("level", "info"), 6)
        pri = FACILITIES.get(self.cfg.get("facility", "local0"), 16) * 8 + sev
        head = f"<{pri}>1 {ev['@timestamp']} {self.hub.host[:255] or '-'} {self.hub.key} {self.pid} {stream} - "
        return head.encode() + _line(ev)

    def _connect(self) -> socket.socket:
        if self.sock is None:
            raw = socket.create_connection((self.cfg["host"], int(self.cfg["port"])), timeout=10)
            if self.cfg["transport"] == "tls":
                raw = _ssl_context(self.cfg).wrap_socket(raw, server_hostname=self.cfg["host"])
            self.sock = raw
        return self.sock

    def send(self, batch: list[tuple[str, dict]]) -> None:
        frames = [self.frame(s, ev) for s, ev in batch]
        try:
            if self.cfg["transport"] == "udp":
                fam = socket.getaddrinfo(self.cfg["host"], int(self.cfg["port"]), type=socket.SOCK_DGRAM)[0]
                with socket.socket(fam[0], socket.SOCK_DGRAM) as s:
                    for f in frames:
                        s.sendto(f[:65000], fam[4])
            else:
                self._connect().sendall(b"".join(str(len(f)).encode() + b" " + f for f in frames))
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class HttpSender:
    def __init__(self, hub: Hub, cfg: dict):
        self.cfg = cfg
        headers = {"Content-Type": "application/x-ndjson", "User-Agent": f"{hub.key}/{hub.version}"}
        auth = os.environ.get("LOG_FORWARD_AUTH", "") if cfg.get("id") == "env" else \
            (hub.decrypt(cfg["auth_enc"]) if cfg.get("auth_enc") else "")
        if auth:
            name, value = parse_header(auth)
            headers[name] = value
        self.headers = headers
        self.timeout = float(cfg.get("timeout", 10))
        ctx = _ssl_context(cfg) if cfg["url"].lower().startswith("https") else None
        # No redirects: a collector that answers 3xx is misconfigured, and following one would
        # send the auth header to wherever it points.
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)

    def send(self, batch: list[tuple[str, dict]]) -> None:
        body = b"\n".join(_line(ev) for _, ev in batch) + b"\n"
        req = urllib.request.Request(self.cfg["url"], data=body, headers=self.headers, method="POST")
        with self.opener.open(req, timeout=self.timeout) as r:
            r.read(65536)

    def close(self) -> None:
        pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401 - urllib hook
        return None


def make_sender(hub: Hub, cfg: dict):
    return SyslogSender(hub, cfg) if cfg["type"] == "syslog" else HttpSender(hub, cfg)


# ─── One thread per destination ──────────────────────────────────────────────

class Forwarder:
    def __init__(self, hub: Hub, cfg: dict):
        self.hub, self.config = hub, dict(cfg)
        self.did = cfg["id"]
        self.streams = set(cfg.get("streams") or STREAMS)
        self.min_idx = LEVELS.index(_level(cfg.get("min_level", "info")))
        self.batch = int(cfg.get("batch_size", 200)) if cfg["type"] == "http" else 100
        self.queue: collections.deque = collections.deque(maxlen=APP_QUEUE)
        self.qlock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"logfwd-{self.did}", daemon=True)
        self.sent = self.failed = self.dropped = 0
        self.last_error = ""
        self.last_error_at: float | None = None
        self.last_sent_at: float | None = None
        self.fails_in_row = 0
        self.retry_at = 0.0
        self.sender = None

    # ── feeding ──
    def offer_app(self, ev: dict) -> None:
        if "app" not in self.streams or LEVELS.index(ev["log"]["level"]) < self.min_idx:
            return
        with self.qlock:
            if len(self.queue) == self.queue.maxlen:
                self.dropped += 1
            self.queue.append(ev)
        self._wake.set()

    def wake(self) -> None:
        self._wake.set()

    def start(self) -> None:
        self._thread.start()
        self._wake.set()

    def stop(self, flush_timeout: float = 0.0) -> None:
        if flush_timeout:
            self.retry_at = 0
            self._wake.set()
            end = time.time() + flush_timeout
            while time.time() < end and self.queue and self.fails_in_row == 0:
                time.sleep(0.05)
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=2)
        if self.sender is not None:
            self.sender.close()

    # ── work ──
    def _cursor(self) -> dict:
        cur = self.hub.db.get_setting(f"logfwd_cursor:{self.did}")
        if not isinstance(cur, dict):
            self.hub.init_cursor(self.did)
            cur = self.hub.db.get_setting(f"logfwd_cursor:{self.did}") or {}
        return {"audit": int(cur.get("audit", 0)), "activity": int(cur.get("activity", 0))}

    def _collect(self) -> tuple[list[tuple[str, dict]], list[dict], dict]:
        out: list[tuple[str, dict]] = []
        with self.qlock:
            app = [self.queue.popleft() for _ in range(min(self.batch, len(self.queue)))]
        out += [("app", ev) for ev in app]
        cur = self._cursor()
        new = dict(cur)
        room = self.batch - len(out)
        for stream, conv in (("audit", self.hub.audit_event), ("activity", self.hub.activity_event)):
            if stream not in self.streams or room <= 0:
                continue
            rows = self.hub.db.all(f"SELECT * FROM {stream} WHERE id > ? ORDER BY id LIMIT ?",
                                   (cur[stream], room))
            for r in rows:
                new[stream] = r["id"]
                ev = conv(r)
                if LEVELS.index(ev["log"]["level"]) >= self.min_idx:
                    out.append((stream, ev))
            room = self.batch - len(out)
        if "audit" not in self.streams or "activity" not in self.streams:
            # keep the cursor of a stream that is not forwarded at the end of the log
            for s in ("audit", "activity"):
                if s not in self.streams:
                    new[s] = (self.hub.db.one(f"SELECT MAX(id) AS n FROM {s}") or {}).get("n") or 0
        return out, app, new if new != cur else {}

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=5.0)
            self._wake.clear()
            if self._stop.is_set():
                break
            while not self._stop.is_set() and time.time() >= self.retry_at:
                try:
                    batch, app, new_cursor = self._collect()
                except Exception as e:  # noqa: BLE001 - database busy etc.
                    self._failed(e, [])
                    break
                if not batch:
                    if new_cursor:
                        self.hub.db.set_setting(f"logfwd_cursor:{self.did}", new_cursor)
                    break
                try:
                    if self.sender is None:
                        self.sender = make_sender(self.hub, self.config)
                    self.sender.send(batch)
                except Exception as e:  # noqa: BLE001 - retried with backoff
                    self._failed(e, app)
                    break
                if new_cursor:
                    self.hub.db.set_setting(f"logfwd_cursor:{self.did}", new_cursor)
                self.sent += len(batch)
                self.last_sent_at = time.time()
                self.fails_in_row = 0

    def _failed(self, e: BaseException, app: list[dict]) -> None:
        with self.qlock:   # put unsent app events back in front; the oldest fall off if full
            for ev in reversed(app):
                if len(self.queue) == self.queue.maxlen:
                    self.dropped += 1
                    break
                self.queue.appendleft(ev)
        if self.sender is not None:
            self.sender.close()
            self.sender = None
        self.failed += 1
        self.fails_in_row += 1
        self.last_error = describe_error(e)
        self.last_error_at = time.time()
        self.retry_at = time.time() + min(MAX_BACKOFF, 2.0 ** min(self.fails_in_row, 9))

    def status(self) -> dict:
        try:
            cur = self._cursor()
            backlog = 0
            for s in ("audit", "activity"):
                if s in self.streams:
                    backlog += (self.hub.db.one(f"SELECT COUNT(*) AS n FROM {s} WHERE id > ?",
                                                (cur[s],)) or {}).get("n", 0)
        except Exception:  # noqa: BLE001
            backlog = -1
        return {"sent": self.sent, "failed": self.failed, "dropped": self.dropped,
                "backlog": backlog + len(self.queue), "last_error": self.last_error,
                "last_error_at": self.last_error_at, "last_sent_at": self.last_sent_at,
                "retrying_at": self.retry_at if self.fails_in_row else None}


# ─── Python logging ────────────────────────────────────

class HubHandler(logging.Handler):
    """Routes stdlib logging into the hub (``app`` dataset)."""

    def __init__(self, echo: bool = True):
        super().__init__()
        self.echo = echo

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.exc_info and self.echo:
                msg += "\n" + logging.Formatter().formatException(record.exc_info)
            LOG.app(record.levelname, msg, echo=self.echo, logger=record.name, ts=record.created)
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)
