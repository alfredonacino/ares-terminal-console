"""
A terminal session: one PTY, one child process, and the bytes between them.

The important property here is that **a session outlives the socket watching
it**. Closing a browser tab, losing wifi, suspending a laptop -- none of those
should kill a running command, and none of them do: the WebSocket goes away,
the session keeps reading its PTY into a scrollback ring, and the next
connection to the same id gets the buffer replayed and carries on. That is the
tmux property people actually want from tmux, and it is why this file has a
registry rather than a function.

Everything here is standard library on POSIX: `pty` and `termios`. Windows has
no equivalent in the standard library, so there the module uses ConPTY through
`pywinpty`, which the Windows desktop build carries. Without it the module
reports itself unsupported rather than pretending (see `unsupported_reason`).
"""

import errno
import os
import queue
import secrets
import shlex
import signal
import struct
import sys
import threading
import time

try:
    import fcntl
    import pty
    import termios
    POSIX_PTY = True
except ImportError:  # pragma: no cover - Windows
    POSIX_PTY = False

WINPTY = None
if not POSIX_PTY:  # pragma: no cover - Windows
    try:
        from winpty import PtyProcess as WINPTY
    except ImportError:
        WINPTY = None

# How much output to keep per session for replay on reattach. 256 KB is a few
# thousand lines of ordinary terminal traffic -- enough to see what happened
# while you were away, small enough that twenty idle sessions cost nothing.
SCROLLBACK_BYTES = 256 * 1024

# Read chunk. Big enough that a `cat` of a large file does not turn into a
# million syscalls, small enough to stay responsive to a keystroke.
READ_CHUNK = 65536

# Output is coalesced for this long before being handed to listeners. Without
# it, a noisy command produces one WebSocket frame per read and the browser
# spends all its time in frame handling instead of drawing.
COALESCE_S = 0.012

def _default_shell() -> str:
    if sys.platform == "win32":
        import shutil
        return (shutil.which("pwsh.exe") or shutil.which("powershell.exe")
                or os.environ.get("COMSPEC") or "cmd.exe")
    return os.environ.get("SHELL") or "/bin/bash"


DEFAULT_SHELL = _default_shell()

# Filled in by set_shell_extras() at startup: the colour scheme and the wrapper
# commands that make a listing readable. Empty until then, so a Session created
# before the app has configured itself simply gets a plain shell.
SHELL_EXTRAS: dict = {}


def set_shell_extras(env: dict) -> None:
    """Environment every session inherits on top of the process's own."""
    global SHELL_EXTRAS
    SHELL_EXTRAS = dict(env or {})


def supported() -> bool:
    return POSIX_PTY or WINPTY is not None


def unsupported_reason() -> str:
    if supported():
        return ""
    return ("this platform has no pty module. Terminals need a POSIX pty, or "
            "on Windows the ConPTY binding pywinpty (pip install pywinpty); "
            "the Windows desktop build of ARES Terminal Console includes it.")


class Session:
    """One PTY and the process on the far end of it."""

    def __init__(self, sid: str, command: str, cols: int = 80, rows: int = 24,
                 cwd: str = "", env: dict = None, label: str = ""):
        self.id = sid
        self.command = command
        self.label = label or command
        self.cols, self.rows = max(2, cols), max(2, rows)
        self.created = time.time()
        self.ended = None
        self.exit_code = None
        self.cwd = cwd or os.path.expanduser("~")

        self.pid = None
        self.fd = None
        self.proc = None              # Windows: the winpty PtyProcess
        self._scrollback = bytearray()
        self._lock = threading.RLock()
        self._listeners = []          # queue.Queue per attached socket
        self._reader = None
        self._closing = False

        # Anti-idle: see nudge(). Off unless somebody turns it on.
        self.antiidle_interval = 0
        self.antiidle_payload = b"\x00"
        self._antiidle = None
        self.last_activity = time.time()

        self._spawn(env or {})

    # ------------------------------------------------------------------ spawn

    def _spawn(self, extra_env: dict) -> None:
        if not supported():
            raise RuntimeError(unsupported_reason())

        env = dict(os.environ)
        # Colour scheme and the ls/ll/la wrappers first, so a caller's own
        # env still overrides them.
        env.update(SHELL_EXTRAS)
        env.update(extra_env)
        # xterm.js speaks xterm-256color; telling the child anything else means
        # colours and key sequences that do not match what the browser renders.
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env.setdefault("LANG", "C.UTF-8")
        # A shell started here is not the shell that started the app, and a
        # child that thinks it is inside tmux/screen will render for that.
        env.pop("TMUX", None)
        env.pop("STY", None)

        if not POSIX_PTY:
            return self._spawn_windows(env)

        argv = shlex.split(self.command) if self.command.strip() else [DEFAULT_SHELL]
        # An ssh pane shares its login with the server tools (see remote.py).
        from app import remote
        argv = remote.pane_argv(self.command) or argv
        pid, fd = pty.fork()
        if pid == 0:  # child
            try:
                os.chdir(self.cwd)
            except OSError:
                pass
            try:
                os.execvpe(argv[0], argv, env)
            except OSError as e:
                # Still the child: write the reason onto the PTY so the user
                # sees it in the pane, then leave without running atexit
                # handlers the parent would also run.
                os.write(2, f"ares-terminal-console: cannot run {argv[0]!r}: {e}\r\n".encode())
                os._exit(127)

        self.pid = pid
        self.fd = fd
        self.set_size(self.rows, self.cols)
        os.set_blocking(fd, False)
        self._reader = threading.Thread(target=self._pump, name=f"pty-{self.id}",
                                        daemon=True)
        self._reader.start()

    def _spawn_windows(self, env: dict) -> None:  # pragma: no cover - Windows
        """ConPTY. The command line goes through as one string: Windows has no
        argv, and splitting it POSIX-style would mangle every backslash."""
        try:
            self.proc = WINPTY.spawn(self.command.strip() or DEFAULT_SHELL,
                                     cwd=self.cwd if os.path.isdir(self.cwd) else None,
                                     env=env, dimensions=(self.rows, self.cols))
        except Exception as e:
            raise RuntimeError(f"cannot start {self.command!r}: {e}") from e
        self.pid = self.proc.pid
        self._reader = threading.Thread(target=self._pump_windows, name=f"conpty-{self.id}",
                                        daemon=True)
        self._reader.start()

    def _pump_windows(self) -> None:  # pragma: no cover - Windows
        """winpty's read blocks and returns text, so there is nothing to select
        on: read, emit, repeat, until the far end closes."""
        while True:
            try:
                chunk = self.proc.read(READ_CHUNK)
            except EOFError:
                break
            except Exception:
                break
            if chunk:
                self._emit(chunk.encode("utf-8", "replace") if isinstance(chunk, str) else chunk)
            elif not self.proc.isalive():
                break
        code = None
        for _ in range(50):
            if not self.proc.isalive():
                code = self.proc.exitstatus
                break
            time.sleep(0.1)
        self._finish(code)

    # ------------------------------------------------------------------- pump

    def _pump(self) -> None:
        import select

        pending = bytearray()
        last_flush = time.monotonic()
        while True:
            fd = self.fd
            if fd is None:          # close() got there first
                break
            try:
                ready, _, _ = select.select([fd], [], [], COALESCE_S)
            except (OSError, ValueError, TypeError):
                break
            if ready:
                try:
                    chunk = os.read(fd, READ_CHUNK)
                except OSError as e:
                    # EIO is how a PTY reports "the child closed the other end",
                    # which is the normal end of every session.
                    if e.errno in (errno.EIO, errno.EBADF):
                        break
                    if e.errno == errno.EAGAIN:
                        chunk = b""
                    else:
                        break
                if not chunk and not ready:
                    continue
                if chunk == b"":
                    break
                pending += chunk

            now = time.monotonic()
            if pending and (now - last_flush >= COALESCE_S or len(pending) >= READ_CHUNK):
                self._emit(bytes(pending))
                pending.clear()
                last_flush = now

        if pending:
            self._emit(bytes(pending))
        self._finish()

    def _emit(self, data: bytes) -> None:
        with self._lock:
            self.last_activity = time.time()
            self._scrollback += data
            if len(self._scrollback) > SCROLLBACK_BYTES:
                del self._scrollback[:len(self._scrollback) - SCROLLBACK_BYTES]
            listeners = list(self._listeners)
        for q in listeners:
            try:
                q.put_nowait(data)
            except queue.Full:
                # A listener that cannot keep up is a browser that has stopped
                # reading. Dropping its bytes is better than stalling the PTY
                # for every other viewer of the same session.
                pass

    def _finish(self, code=None) -> None:
        if self.pid and POSIX_PTY:
            try:
                _, status = os.waitpid(self.pid, 0)
                code = os.waitstatus_to_exitcode(status)
            except (ChildProcessError, OSError):
                code = None
        with self._lock:
            self.ended = time.time()
            self.exit_code = code
            listeners = list(self._listeners)
        for q in listeners:
            try:
                q.put_nowait(None)     # sentinel: the session is over
            except queue.Full:
                pass
        hook = getattr(self, "on_end", None)
        if hook:
            try:
                hook(self)
            except Exception:      # a bookkeeping failure must not kill the pump
                pass

    # -------------------------------------------------------------- attach/io

    def attach(self) -> queue.Queue:
        """Subscribe to output. Returns a queue that yields bytes, then None."""
        q = queue.Queue(maxsize=512)
        with self._lock:
            self._listeners.append(q)
        return q

    def detach(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._listeners:
                self._listeners.remove(q)

    def scrollback(self) -> bytes:
        with self._lock:
            return bytes(self._scrollback)

    def write(self, data) -> None:
        if self.ended:
            return
        if self.proc is not None:  # pragma: no cover - Windows
            if isinstance(data, bytes):
                data = data.decode("utf-8", "replace")
            self.last_activity = time.time()
            try:
                self.proc.write(data)
            except Exception:
                pass
            return
        if self.fd is None:
            return
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        self.last_activity = time.time()
        try:
            # A big paste will not go out in one write on a PTY; the loop is
            # what stops the tail of it being silently dropped.
            while data:
                written = os.write(self.fd, data)
                data = data[written:]
        except OSError:
            pass

    def set_size(self, rows: int, cols: int) -> None:
        self.rows, self.cols = max(2, int(rows)), max(2, int(cols))
        if self.proc is not None:  # pragma: no cover - Windows
            try:
                self.proc.setwinsize(self.rows, self.cols)
            except Exception:
                pass
            return
        if self.fd is None:
            return
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", self.rows, self.cols, 0, 0))
            # Curses apps redraw on SIGWINCH and nothing else; the ioctl alone
            # leaves vim rendering at the old size.
            os.killpg(os.getpgid(self.pid), signal.SIGWINCH)
        except (OSError, ValueError):
            pass

    def send_signal(self, name: str) -> bool:
        """Signal the foreground process group, the way Ctrl-C does."""
        if self.proc is not None:  # pragma: no cover - Windows
            # ConPTY turns a typed ^C into CTRL_C_EVENT for the console's
            # processes, which is the nearest Windows has to a process group.
            name = name.upper()
            try:
                if name == "INT":
                    self.proc.write("\x03")
                elif name in ("TERM", "KILL", "HUP", "QUIT"):
                    self.proc.terminate(force=True)
                else:
                    return False
                return True
            except Exception:
                return False
        sig = {"INT": signal.SIGINT, "TERM": signal.SIGTERM, "QUIT": signal.SIGQUIT,
               "HUP": signal.SIGHUP, "KILL": signal.SIGKILL}.get(name.upper())
        if sig is None or self.pid is None:
            return False
        try:
            os.killpg(os.getpgid(self.pid), sig)
            return True
        except (OSError, ValueError):
            return False

    @property
    def alive(self) -> bool:
        return self.ended is None

    # -------------------------------------------------------------- anti-idle

    def set_antiidle(self, interval: int, payload: bytes = b"\x00") -> None:
        """Write a harmless byte on an interval so a *remote* does not time out.

        Distinct from the WebSocket ping, which only keeps the browser link up.
        This is for the far end -- an ssh session to a bastion that drops you
        after ten quiet minutes does not care how healthy your browser socket
        is.

        NUL is the default payload because a line editor discards it: it is
        traffic on the wire and nothing in the buffer. It is still a write into
        somebody's shell, so this is off unless asked for, per session, and the
        pane says so while it is on.
        """
        self.antiidle_interval = max(0, int(interval))
        self.antiidle_payload = payload or b"\x00"
        if self._antiidle is None and self.antiidle_interval:
            self._antiidle = threading.Thread(target=self._nudge_loop,
                                              name=f"antiidle-{self.id}", daemon=True)
            self._antiidle.start()

    def _nudge_loop(self) -> None:
        while self.alive:
            interval = self.antiidle_interval
            if not interval:
                time.sleep(1.0)
                continue
            time.sleep(1.0)
            if not self.alive or not self.antiidle_interval:
                continue
            # Only nudge a session that has actually gone quiet; writing into
            # one somebody is typing in would be both pointless and rude.
            if time.time() - self.last_activity >= self.antiidle_interval:
                self.write(self.antiidle_payload)
                self.last_activity = time.time()

    # ------------------------------------------------------------------ close

    def close(self, force: bool = False) -> None:
        if self._closing:
            return
        self._closing = True
        if self.proc is not None:  # pragma: no cover - Windows
            try:
                self.proc.terminate(force=True)
            except Exception:
                pass
            return
        if self.pid:
            try:
                os.killpg(os.getpgid(self.pid), signal.SIGKILL if force else signal.SIGHUP)
            except (OSError, ValueError):
                pass
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def info(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "command": self.command,
            "cwd": self.cwd,
            "cols": self.cols,
            "rows": self.rows,
            "pid": self.pid,
            "created": self.created,
            "ended": self.ended,
            "exit_code": self.exit_code,
            "alive": self.alive,
            "viewers": len(self._listeners),
            "antiidle": self.antiidle_interval,
            "idle_for": round(time.time() - self.last_activity, 1),
            "bytes": len(self._scrollback),
            "ssh": self.ssh_label(),
        }

    def ssh_label(self) -> str:
        """user@host[:port] when this pane is an SSH connection, else ""."""
        from app import remote
        target = remote.parse(self.command)
        return remote.label(target) if target else ""


class Registry:
    """Every live session, and the reason a dropped browser is survivable."""

    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def create(self, command: str = "", cols: int = 80, rows: int = 24,
               cwd: str = "", env: dict = None, label: str = "") -> Session:
        sid = secrets.token_urlsafe(9)
        session = Session(sid, command or DEFAULT_SHELL, cols=cols, rows=rows,
                          cwd=cwd, env=env, label=label)
        with self._lock:
            self._sessions[sid] = session
        return session

    def get(self, sid: str):
        with self._lock:
            return self._sessions.get(sid)

    def list(self) -> list:
        with self._lock:
            return [s.info() for s in self._sessions.values()]

    def kill(self, sid: str, force: bool = True) -> bool:
        with self._lock:
            session = self._sessions.pop(sid, None)
        if session is None:
            return False
        session.close(force=force)
        return True

    def reap(self, keep_dead_for: float = 300.0) -> int:
        """Forget sessions that ended a while ago.

        Not immediately: a command that failed in a pane the user had closed is
        exactly the thing they come back to look for, so a dead session stays
        readable for a few minutes before its scrollback is dropped.
        """
        cutoff = time.time() - keep_dead_for
        with self._lock:
            gone = [sid for sid, s in self._sessions.items()
                    if s.ended is not None and s.ended < cutoff]
            for sid in gone:
                self._sessions.pop(sid, None)
        return len(gone)

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close(force=True)
