"""
What was run, and where — the connection history.

Two lists, kept apart on purpose:

  history    every command a pane was opened with, newest first, with when it
             started, when it ended and how. Automatic; you never curate it.

  saved      the ones you asked to keep, with a name. A bastion you reach for
             every day should not have to be found in a list of four hundred.

  commands   each command line sent to a pane, read back off the terminal
             screen when Enter is pressed (so what tab-completion and the
             arrow keys produced, not the keys), with the pane and server.

  servers    every SSH destination connected to: first and last time, how
             many times, and the sessions -- when each began and ended.

All live in one JSON file under the data directory the host hands over, so a
session started from the suite and one started standalone share nothing by
accident and everything on purpose. Standard library only.

Nothing here stores a secret. A command line is recorded verbatim, which is
why `redact()` exists: `sshpass -p hunter2` is a command somebody will type,
and it must not end up on disk in plain text because this file was convenient.
"""

import json
import os
import re
import threading
import time

MAX_HISTORY = 500
MAX_COMMANDS = 5000
MAX_SERVER_SESSIONS = 30
MAX_COMMAND_LEN = 2000

# Flags whose *value* is a secret. Deliberately long-form only: a wrong guess
# here silently corrupts a command somebody wants to re-run, and bare `-p` is
# the trap -- it is a password to sshpass and mysql, and a PORT to ssh and scp.
# Redacting `ssh -p 2222` would hand back a command that no longer connects.
_SECRET_FLAGS = re.compile(
    r"(--(?:password|passwd|pass|token|secret|api-key|apikey|auth-token)[= ])(\S+)",
    re.IGNORECASE)

# ...so bare -p is redacted only for the tools where it means a password, named
# one at a time rather than guessed.
_PASSWORD_TOOLS = re.compile(
    r"\b(sshpass\s+(?:\S+\s+)*?-p\s*|mysql(?:dump|admin)?\s+(?:\S+\s+)*?-p)(\S+)",
    re.IGNORECASE)

# A URL with credentials in it: scheme://user:secret@host
_URL_CREDS = re.compile(r"(\w+://[^\s:@/]+):([^\s@/]+)@")


def redact(command: str) -> str:
    """Blank out anything that looks like a password before it is written down."""
    out = _SECRET_FLAGS.sub(lambda m: m.group(1) + "***", command)
    out = _PASSWORD_TOOLS.sub(lambda m: m.group(1) + "***", out)
    out = _URL_CREDS.sub(lambda m: m.group(1) + ":***@", out)
    return out


class History:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._data = {"version": 1, "history": [], "saved": [], "commands": [], "servers": {}}
        self.load()

    # ------------------------------------------------------------------- disk

    def load(self) -> None:
        with self._lock:
            if not os.path.isfile(self.path):
                return
            try:
                raw = json.loads(open(self.path, encoding="utf-8").read())
            except (OSError, ValueError):
                # A corrupt history is preferences, not data: losing it must
                # never stop the app from opening a terminal.
                try:
                    os.replace(self.path, self.path + ".broken")
                except OSError:
                    pass
                return
            if isinstance(raw, dict):
                self._data["history"] = [e for e in raw.get("history", []) if isinstance(e, dict)]
                self._data["saved"] = [e for e in raw.get("saved", []) if isinstance(e, dict)]
                self._data["commands"] = [e for e in raw.get("commands", []) if isinstance(e, dict)]
                if isinstance(raw.get("servers"), dict):
                    self._data["servers"] = raw["servers"]

    def save(self) -> None:
        with self._lock:
            parent = os.path.dirname(os.path.abspath(self.path))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(self._data, fh, indent=1)
                if os.name != "nt":
                    os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
            except OSError:
                pass

    # ---------------------------------------------------------------- history

    def record(self, session_id: str, command: str, cwd: str = "", label: str = "") -> dict:
        entry = {
            "id": session_id,
            "command": redact(command),
            "cwd": cwd,
            "label": label or redact(command),
            "started": time.time(),
            "ended": None,
            "exit_code": None,
        }
        with self._lock:
            self._data["history"].insert(0, entry)
            del self._data["history"][MAX_HISTORY:]
        self.save()
        return entry

    def finish(self, session_id: str, exit_code=None) -> None:
        now = time.time()
        with self._lock:
            for entry in self._data["history"]:
                if entry.get("id") == session_id and entry.get("ended") is None:
                    entry["ended"] = now
                    entry["exit_code"] = exit_code
                    break
            for server in self._data["servers"].values():
                for s in server.get("sessions", []):
                    if s.get("id") == session_id and s.get("ended") is None:
                        s["ended"] = now
                        s["exit_code"] = exit_code
        self.save()

    # --------------------------------------------------------------- commands

    def log_command(self, session_id: str, command: str, pane: str = "",
                    connection: str = "", how: str = "typed") -> dict:
        command = (command or "").strip()[:MAX_COMMAND_LEN]
        if not command:
            return {}
        entry = {"t": time.time(), "session": session_id, "pane": redact(pane),
                 "connection": connection, "command": redact(command), "how": how}
        with self._lock:
            self._data["commands"].insert(0, entry)
            del self._data["commands"][MAX_COMMANDS:]
            if connection in self._data["servers"]:
                server = self._data["servers"][connection]
                server["commands"] = server.get("commands", 0) + 1
        self.save()
        return entry

    def commands(self, session_id: str = "", connection: str = "", query: str = "",
                 limit: int = 500) -> list:
        q = (query or "").lower()
        with self._lock:
            rows = [c for c in self._data["commands"]
                    if (not session_id or c.get("session") == session_id)
                    and (not connection or c.get("connection") == connection)
                    and (not q or q in c.get("command", "").lower()
                         or q in c.get("pane", "").lower())]
        return rows[:max(1, min(limit, MAX_COMMANDS))]

    def clear_commands(self) -> None:
        with self._lock:
            self._data["commands"] = []
            for server in self._data["servers"].values():
                server["commands"] = 0
        self.save()

    # ---------------------------------------------------------------- servers

    def note_connection(self, session_id: str, connection: str, command: str,
                        label: str = "") -> None:
        """An SSH pane was opened to `connection` (user@host[:port])."""
        if not connection:
            return
        now = time.time()
        user, _, hostport = connection.rpartition("@")
        host, _, port = hostport.partition(":")
        with self._lock:
            server = self._data["servers"].setdefault(connection, {
                "connection": connection, "host": host, "user": user, "port": port,
                "first": now, "count": 0, "commands": 0, "sessions": []})
            server.update(last=now, command=redact(command), label=label or server.get("label", ""))
            server["count"] = server.get("count", 0) + 1
            server["sessions"].insert(0, {"id": session_id, "started": now,
                                          "ended": None, "exit_code": None})
            del server["sessions"][MAX_SERVER_SESSIONS:]
        self.save()

    def servers(self) -> list:
        with self._lock:
            return sorted((json.loads(json.dumps(s)) for s in self._data["servers"].values()),
                          key=lambda s: -s.get("last", 0))

    def forget_server(self, connection: str) -> bool:
        with self._lock:
            gone = self._data["servers"].pop(connection, None) is not None
        if gone:
            self.save()
        return gone

    def clear(self) -> None:
        with self._lock:
            self._data["history"] = []
        self.save()

    # ------------------------------------------------------------------ saved

    def save_connection(self, name: str, command: str, cwd: str = "") -> dict:
        entry = {"name": name.strip() or redact(command),
                 "command": redact(command), "cwd": cwd, "added": time.time()}
        with self._lock:
            self._data["saved"] = [e for e in self._data["saved"]
                                   if e.get("name") != entry["name"]]
            self._data["saved"].insert(0, entry)
        self.save()
        return entry

    def forget_connection(self, name: str) -> bool:
        with self._lock:
            before = len(self._data["saved"])
            self._data["saved"] = [e for e in self._data["saved"] if e.get("name") != name]
            changed = len(self._data["saved"]) != before
        if changed:
            self.save()
        return changed

    # ------------------------------------------------------------------- read

    def snapshot(self) -> dict:
        with self._lock:
            return {"history": list(self._data["history"][:200]),
                    "saved": list(self._data["saved"])}
