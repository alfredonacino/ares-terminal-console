"""
Apex Terminal — the local backend.

Serves the UI, opens PTYs, and carries their bytes over WebSocket. Standard
library only, Python 3.8+, because a terminal is what you reach for when a
machine is already in a bad way and "pip install first" is the wrong answer.

    GET  /                     the UI
    GET  /ws?session=<id>      attach to a session (WebSocket)
    GET  /api/sessions         what is running
    POST /api/sessions         open a new one            {command, cwd, cols, rows}
    POST /api/sessions/<id>/kill
    GET  /api/history          history + saved connections
    POST /api/history/save     keep one                  {name, command, cwd}
    POST /api/history/forget   drop one                  {name}
    POST /api/history/clear

Framing is the one rule this app inherits from the suite: standalone it refuses
to be framed at all, and under ApexBuild it names exactly the one loopback
origin the host passes in. See docs/EMBEDDING.md in the ApexBuild repository.
"""

import json
import mimetypes
import os
import pathlib
import re
import signal
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import agent, pty_session, shell_env, sso       # noqa: E402
from app.history import History                          # noqa: E402
from app.websocket import WebSocket, WebSocketClosed, is_upgrade  # noqa: E402

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

APP_NAME = "Apex Terminal"


def _manifest_version(default: str = "0.0.0") -> str:
    """The version out of apexmodule.toml.

    Read rather than repeated, so the number the About box shows and the number
    ApexBuild lists in its sidebar cannot disagree -- there is one place to
    change it. tomllib is standard library from 3.11, which is the floor this
    app already stands on, so this adds no dependency.
    """
    try:
        import tomllib
        path = pathlib.Path(__file__).resolve().parent.parent / "apexmodule.toml"
        with path.open("rb") as fh:
            return str(tomllib.load(fh)["module"]["version"])
    except Exception:
        # A packaged build with no manifest beside it still has to start.
        return default


APP_VERSION = _manifest_version()
AUTHOR = "Alfredo Nacino"

# An embed origin is only ever a loopback HTTP origin handed over by the host
# process that started us. Validating the shape -- rather than trusting the
# string -- means a stray environment variable cannot turn the app into
# something any website may frame.
LOOPBACK_ORIGIN = re.compile(r"^http://(127\.0\.0\.1|localhost|\[::1\]):\d{1,5}$")

# Set in serve() when the suite started us; None when we were run alone, in
# which case there is nobody to trust and no ticket is accepted.
SSO = None

# What every agent ask cost. Set in serve(), beside the history file.
LEDGER = None
# Who the shell says is using this. Displayed, and written into the history so
# an audit of what was run has a name against it.
SSO_USER = {}

REGISTRY = pty_session.Registry()
HISTORY = None          # set in serve()
SHIMS = {}              # set in serve(): which wrapper commands exist
EMBED_ORIGIN = ""


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log(level: str, msg: str) -> None:
    sys.stdout.write(f"{now_iso()}  {level:<5} {msg}\n")
    sys.stdout.flush()


def set_embed_origin(origin: str) -> str:
    """Allow one loopback origin to frame this app. Returns what was accepted."""
    global EMBED_ORIGIN
    origin = (origin or "").strip()
    EMBED_ORIGIN = origin if LOOPBACK_ORIGIN.match(origin) else ""
    return EMBED_ORIGIN


def security_headers() -> dict:
    """The headers every response carries.

    Framing is the interesting one. Standalone this app refuses to be framed at
    all; under ApexBuild it is framed by a shell on a *different loopback port*
    and therefore a different origin, so the host passes its origin in and we
    name it, and only it.

    X-Frame-Options is dropped in that case rather than kept: its only
    multi-origin form, ALLOW-FROM, is dead in every current browser, so a
    browser honouring it would block the frame that CSP just permitted.
    """
    frame_ancestors = f"'self' {EMBED_ORIGIN}" if EMBED_ORIGIN else "'self'"
    headers = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            # The terminal's own socket. ws: is loopback here; the CSP cannot
            # express "same origin but ws", so the scheme is listed.
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'none'; "
            f"frame-ancestors {frame_ancestors}"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }
    if not EMBED_ORIGIN:
        headers["X-Frame-Options"] = "SAMEORIGIN"
    return headers


class Handler(BaseHTTPRequestHandler):
    server_version = "ApexTerminal"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    # ---------------------------------------------------------------- plumbing

    def _send(self, status: int, body: bytes, ctype: str, extra: dict = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in security_headers().items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, obj, status: int = 200):
        self._send(status, json.dumps(obj).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        # Always drain the body, even for handlers that ignore it: anything
        # left in the socket becomes the first bytes of the next request on a
        # keep-alive connection, which the parser then rejects.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(min(length, 1 << 20)) if length > 0 else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return {}

    def _query(self) -> dict:
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def _q1(self, name, default=""):
        v = self._query().get(name)
        return v[0] if v else default

    # ------------------------------------------------------------------- verbs

    def _accept_sso(self, path: str):
        """Take the identity out of a ticket, then get it out of the URL.

        The redirect matters as much as the check: a ticket left in the address
        bar is in the history, in a screenshot and in anything that logs a
        referrer. It is single-use anyway, but the tidy thing is for it to
        exist for exactly one request.
        """
        global SSO_USER
        ticket = self._q1(sso.QUERY_PARAM)
        if not ticket or SSO is None:
            return False
        try:
            payload = SSO.verify(ticket)
        except ValueError as e:
            log("WARN", f"refused a single sign-on ticket: {e}")
            return False
        SSO_USER = {"username": payload["sub"], "name": payload.get("name", ""),
                    "role": payload.get("role", "user")}
        log("INFO", f"single sign-on: {payload['sub']} ({payload.get('role')})")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        query.pop(sso.QUERY_PARAM, None)
        rest = urllib.parse.urlencode(query, doseq=True)
        self.send_response(303)
        self.send_header("Location", path + (("?" + rest) if rest else ""))
        self.send_header("Content-Length", "0")
        for k, v in security_headers().items():
            self.send_header(k, v)
        self.end_headers()
        return True

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path

        if self._q1(sso.QUERY_PARAM) and self._accept_sso(path):
            return

        if path == "/ws":
            return self._websocket()
        if path == "/api/health":
            return self._json({"ok": True, "app": APP_NAME,
                               "version": APP_VERSION,
                               "user": SSO_USER or None,
                               "embedded": bool(EMBED_ORIGIN),
                               "supported": pty_session.supported(),
                               "reason": pty_session.unsupported_reason(),
                               "sessions": len(REGISTRY.list()),
                               "time": now_iso()})
        if path == "/api/sessions":
            return self._json({"ok": True, "sessions": REGISTRY.list()})
        if path == "/api/history":
            return self._json({"ok": True, **HISTORY.snapshot()})
        if path == "/api/colors":
            return self._json({"ok": True,
                               "legend": [{"label": l, "sgr": c} for l, c in shell_env.LEGEND],
                               "shims": SHIMS})
        if path == "/api/agent/state":
            # Asked on every page load, so it must be cheap and must never
            # raise: the answer "no" is what draws the bar as unavailable.
            return self._json({"ok": True, **agent.state()})
        if path == "/api/agent/costs":
            return self._json({"ok": True, **LEDGER.analysis()})
        return self._static(path)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        body = self._body()

        if path == "/api/sessions":
            if not pty_session.supported():
                return self._json({"ok": False, "error": pty_session.unsupported_reason()},
                                  status=501)
            command = str(body.get("command") or "").strip()
            cwd = str(body.get("cwd") or "")
            try:
                session = REGISTRY.create(
                    command=command,
                    cols=int(body.get("cols") or 80),
                    rows=int(body.get("rows") or 24),
                    cwd=cwd,
                    label=str(body.get("label") or ""),
                )
            except (OSError, RuntimeError, ValueError) as e:
                return self._json({"ok": False, "error": str(e)}, status=500)
            HISTORY.record(session.id, command or pty_session.DEFAULT_SHELL,
                           cwd=session.cwd, label=str(body.get("label") or ""))
            log("INFO", f"session {session.id} <- {command or pty_session.DEFAULT_SHELL}")
            return self._json({"ok": True, "session": session.info()})

        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[1] == "sessions" and parts[3] == "kill":
            ok = REGISTRY.kill(parts[2])
            return self._json({"ok": ok})

        if path == "/api/history/save":
            name = str(body.get("name") or "")
            command = str(body.get("command") or "")
            if not command:
                return self._json({"ok": False, "error": "command is required"}, status=400)
            return self._json({"ok": True,
                               "saved": HISTORY.save_connection(name, command,
                                                                str(body.get("cwd") or ""))})
        if path == "/api/history/forget":
            return self._json({"ok": HISTORY.forget_connection(str(body.get("name") or ""))})
        if path == "/api/history/clear":
            HISTORY.clear()
            return self._json({"ok": True})

        if path == "/api/agent/ask":
            prompt = str(body.get("prompt") or "")
            result = agent.ask(prompt,
                               cwd=str(body.get("cwd") or ""),
                               model=str(body.get("model") or ""))
            # Recorded whichever way it went. An ask that failed after the
            # model had already run still cost something, and a ledger that
            # only counts successes understates the bill.
            usage = result.get("usage") or {}
            if usage:
                LEDGER.record(prompt, usage, ok=result.get("ok", False))
            if result.get("ok"):
                log("INFO", f"agent ask ({usage.get('duration_ms', '?')}ms, "
                            f"${usage.get('cost') or 0:.4f}): {prompt[:60]}")
            else:
                log("WARN", f"agent ask failed: {result.get('error', '')[:120]}")
            return self._json(result, status=200 if result.get("ok") else 400)

        if path == "/api/agent/costs/clear":
            LEDGER.clear()
            return self._json({"ok": True, **LEDGER.analysis()})

        return self._json({"ok": False, "error": "unknown endpoint"}, status=404)

    # --------------------------------------------------------------- websocket

    def _websocket(self):
        if not is_upgrade(self.headers):
            return self._json({"ok": False, "error": "expected a websocket upgrade"},
                              status=400)

        # Same-origin check. The browser sends Origin on a WebSocket handshake
        # and does NOT apply CORS to it, so without this any page on the
        # internet could open a socket to this port and get a shell. The two
        # origins that may: ourselves, and the ApexBuild shell framing us.
        origin = self.headers.get("Origin", "")
        allowed = {f"http://{self.headers.get('Host', '')}"}
        if EMBED_ORIGIN:
            allowed.add(EMBED_ORIGIN)
        if origin and origin not in allowed:
            log("WARN", f"refused websocket from origin {origin!r}")
            return self._json({"ok": False, "error": "origin not allowed"}, status=403)

        sid = self._q1("session")
        session = REGISTRY.get(sid) if sid else None
        if session is None:
            return self._json({"ok": False, "error": "unknown session"}, status=404)

        try:
            ws = WebSocket.upgrade(self)
        except Exception as e:
            log("WARN", f"websocket upgrade failed: {e}")
            return

        log("INFO", f"attach {session.id} ({session.label})")
        pump(ws, session)
        log("INFO", f"detach {session.id}")

    # ------------------------------------------------------------------ static

    def _static(self, path: str):
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC / rel).resolve()
        # Containment check before touching the filesystem: the path came off
        # the wire.
        if STATIC.resolve() not in target.parents or not target.is_file():
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith(("javascript", "json")):
            ctype += "; charset=utf-8"
        try:
            self._send(200, target.read_bytes(), ctype)
        except OSError as e:
            self._send(500, str(e).encode(), "text/plain; charset=utf-8")


def pump(ws: WebSocket, session) -> None:
    """Carry bytes both ways until one end goes away.

    Output runs on its own thread so a quiet socket never stalls the PTY, and
    the keepalive pinger runs on a third. The read loop below owns the socket's
    read side and nothing else touches it.
    """
    queue_ = session.attach()
    stop = threading.Event()

    def _out():
        # Replay first: a reattach should show what happened while nobody was
        # watching, which is the entire point of sessions outliving sockets.
        try:
            backlog = session.scrollback()
            if backlog:
                ws.send_json({"t": "out", "d": backlog.decode("utf-8", "replace"),
                              "replay": True})
            ws.send_json({"t": "info", "session": session.info()})
        except WebSocketClosed:
            stop.set()
            return
        while not stop.is_set():
            try:
                chunk = queue_.get(timeout=0.5)
            except Exception:
                continue
            if chunk is None:
                try:
                    ws.send_json({"t": "exit", "code": session.exit_code})
                except WebSocketClosed:
                    pass
                stop.set()
                return
            try:
                ws.send_json({"t": "out", "d": chunk.decode("utf-8", "replace")})
            except WebSocketClosed:
                stop.set()
                return

    writer = threading.Thread(target=_out, name=f"ws-out-{session.id}", daemon=True)
    writer.start()
    ws.start_keepalive(on_dead=stop.set)

    try:
        while not stop.is_set():
            message = ws.recv()
            if message is None:
                break
            if isinstance(message, bytes):
                session.write(message)
                continue
            try:
                msg = json.loads(message)
            except ValueError:
                session.write(message)
                continue

            kind = msg.get("t")
            if kind == "in":
                session.write(msg.get("d", ""))
            elif kind == "resize":
                session.set_size(msg.get("rows", 24), msg.get("cols", 80))
            elif kind == "signal":
                session.send_signal(str(msg.get("sig", "INT")))
            elif kind == "antiidle":
                session.set_antiidle(int(msg.get("interval") or 0))
                try:
                    ws.send_json({"t": "info", "session": session.info()})
                except WebSocketClosed:
                    break
            elif kind == "ping":
                try:
                    ws.send_json({"t": "pong", "at": time.time()})
                except WebSocketClosed:
                    break
    finally:
        stop.set()
        session.detach(queue_)
        ws.close()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, WebSocketClosed)):
            return   # a browser closing a tab is not an error
        super().handle_error(request, client_address)


def _reaper():
    """Forget long-dead sessions so a week-old window does not hold megabytes."""
    while True:
        time.sleep(60)
        REGISTRY.reap()


def serve(host: str = "127.0.0.1", port: int = 0, data_dir: str = "",
          embed_origin: str = "", open_browser: bool = False) -> int:
    """Start the app and block until told to stop."""
    global HISTORY, LEDGER

    if data_dir:
        os.makedirs(data_dir, exist_ok=True)
    else:
        data_dir = os.path.join(
            os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"),
            "apex-terminal")
        os.makedirs(data_dir, exist_ok=True)
    HISTORY = History(os.path.join(data_dir, "history.json"))
    LEDGER = agent.Ledger(os.path.join(data_dir, "agent-costs.json"))

    # Colour. A pane is monochrome without both halves of this: a scheme in
    # LS_COLORS, and an `ls` that has been asked to use it. See shell_env.py.
    global SHIMS
    SHIMS = shell_env.build_shims(os.path.join(data_dir, "bin"))
    shims = SHIMS
    pty_session.set_shell_extras(shell_env.environment(os.path.join(data_dir, "bin")))

    global SSO
    SSO = sso.from_environment("terminal")
    if SSO:
        log("INFO", "single sign-on enabled; tickets from the ApexBuild shell "
                    "will be accepted")

    if embed_origin and not set_embed_origin(embed_origin):
        log("WARN", f"ignoring --embed-origin {embed_origin!r}: only a loopback "
                    "http origin such as http://127.0.0.1:8800 is accepted")

    httpd = Server((host, port), Handler)
    actual = httpd.server_address[1]
    browse_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    url = f"http://{browse_host}:{actual}/"

    log("INFO", f"{APP_NAME} on {url}")
    log("INFO", f"history: {HISTORY.path}")
    if shims:
        log("INFO", "colour: " + ", ".join(f"{k} -> {v}" for k, v in shims.items()))
    else:
        log("WARN", "no ls found; listings will not be coloured")
    if EMBED_ORIGIN:
        log("INFO", f"embedded: {EMBED_ORIGIN} may frame this app")
    if not pty_session.supported():
        log("WARN", pty_session.unsupported_reason())
    if host not in ("127.0.0.1", "localhost", "::1"):
        log("WARN", f"listening on {host} — this app opens shells and has no "
                    "authentication of its own. Keep it on loopback.")

    def _shutdown(signum, frame):
        log("INFO", "shutting down; closing every session")
        REGISTRY.close_all()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass

    threading.Thread(target=_reaper, name="reaper", daemon=True).start()

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    finally:
        REGISTRY.close_all()
        httpd.server_close()
    return 0
