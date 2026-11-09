"""
ARES Terminal Console as a desktop application.

Runs the server on 127.0.0.1 on a free port, with an access token so that no
other user of the machine can open a shell through it, and shows it in a window:

* Windows and macOS: a native window (pywebview: WebView2 / WKWebView).
* Linux: an app window of Chrome, Chromium, Brave or Edge when one is
  installed, otherwise a tab of the default browser.

The first copy owns the server. Starting the app again does not start a second
server -- that would split your sessions across two processes -- it opens
another window onto the first one. Closing the first copy's window quits the
app and ends its sessions, as closing a terminal emulator does.

    ares-terminal-console              start, or open another window
    ares-terminal-console --self-test  start on a temporary data folder, check, exit
"""

import argparse
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import server  # noqa: E402

APP_NAME = server.APP_NAME
APP_ID = "ares-terminal-console"


def data_dir() -> Path:
    d = Path(os.environ.get("ARES_DATA_DIR") or server.default_data_dir())
    d.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        d.chmod(0o700)
    return d


# ----------------------------------------------------------- one server only

class InstanceLock:
    """An OS file lock held for the life of the process. The OS drops it when
    the process ends, however it ends, so a held lock means a live server."""

    def __init__(self, path: Path):
        self.path, self.fh = path, None

    def acquire(self) -> bool:
        fh = open(self.path, "a+")
        try:
            if sys.platform == "win32":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return False
        self.fh = fh
        return True

    def release(self) -> None:
        if self.fh is not None:
            self.fh.close()
            self.fh = None


def running_url(d: Path) -> str:
    """The URL of the copy that holds the lock, if it answers."""
    try:
        info = json.loads((d / "instance.json").read_text())
        port = int(info["port"])
        token = str(info["token"])
    except (OSError, ValueError, KeyError, TypeError):
        return ""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=3) as r:
            if json.loads(r.read().decode()).get("app") != APP_NAME:
                return ""
    except (OSError, ValueError):
        return ""
    return f"http://127.0.0.1:{port}/?{server.TOKEN_PARAM}={token}"


# ------------------------------------------------------------------- window

def host_environment() -> None:
    """A frozen Linux build points LD_LIBRARY_PATH at its bundled libraries,
    and programs started from it -- the browser, and every shell in every pane
    -- would inherit that and load the bundle's old libstdc++. Put back what
    PyInstaller saved, so children see the system's own libraries."""
    if not getattr(sys, "frozen", False):
        return
    for var in ("LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH"):
        orig = os.environ.pop(f"{var}_ORIG", None)
        if orig is not None:
            os.environ[var] = orig
        else:
            os.environ.pop(var, None)


def _browser_app_window(url: str, profile: Path):
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                 "brave-browser", "brave", "microsoft-edge", "microsoft-edge-stable"):
        exe = shutil.which(name)
        if exe:
            # A profile of its own makes this a separate browser process that
            # ends when the window closes, rather than a tab of the user's own.
            return subprocess.Popen(
                [exe, f"--app={url}", f"--user-data-dir={profile}", "--no-first-run",
                 "--no-default-browser-check", f"--class={APP_ID}", "--window-size=1280,820"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return None


def _stop_group(proc) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=4)
            return
        except subprocess.TimeoutExpired:
            continue


def show(url: str, d: Path, quit_event: threading.Event) -> None:
    """Show url in a window and return when it is closed or quit_event is set."""
    if sys.platform in ("win32", "darwin"):
        try:
            import webview
        except ImportError:
            webview = None
        if webview is not None:
            win = webview.create_window(APP_NAME, url, width=1280, height=820,
                                        min_size=(720, 480), background_color="#0d1117")

            def _watch():
                quit_event.wait()
                try:
                    win.destroy()
                except Exception:
                    pass
            threading.Thread(target=_watch, daemon=True).start()
            webview.start(private_mode=False, storage_path=str(d / "webview"))
            return

    proc = _browser_app_window(url, d / "browser") if sys.platform.startswith("linux") else None
    if proc is not None:
        started = time.monotonic()
        try:
            while proc.poll() is None and not quit_event.is_set():
                time.sleep(0.4)
        finally:
            _stop_group(proc)
        # A browser that quit within seconds handed off or failed to start.
        if quit_event.is_set() or time.monotonic() - started > 5:
            return
    webbrowser.open(url)
    print(f"{APP_NAME} is running at {url}\nPress Ctrl+C here to stop it.", flush=True)
    try:
        quit_event.wait()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------- run

def run() -> int:
    d = data_dir()
    lock = InstanceLock(d / "instance.lock")
    if not lock.acquire():
        url = running_url(d)
        if url:
            show(url, d / "second-window", threading.Event())
            return 0
        print(f"another copy of {APP_NAME} holds {d / 'instance.lock'} but does not "
              "answer; stop it and start again", file=sys.stderr)
        return 1

    token = secrets.token_urlsafe(32)
    httpd, url = server.start(host="127.0.0.1", port=0, data_dir=str(d), access_token=token)
    port = httpd.server_address[1]
    fd = os.open(d / "instance.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"port": port, "token": token, "pid": os.getpid()}, fh)
    threading.Thread(target=httpd.serve_forever, name="server", daemon=True).start()

    quit_event = threading.Event()
    for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), lambda *_: quit_event.set())
            except (ValueError, OSError):
                pass
    try:
        show(url, d, quit_event)
    finally:
        server.REGISTRY.close_all()
        httpd.shutdown()
        httpd.server_close()
        try:
            (d / "instance.json").unlink()
        except OSError:
            pass
        lock.release()
    return 0


# ---------------------------------------------------------------- self-test

def self_test() -> int:
    """What a frozen bundle must prove before it ships: the server answers, the
    token gate holds, the UI and xterm.js were bundled, and a real shell runs
    in a real PTY (ConPTY on Windows) and its output comes back."""
    d = Path(tempfile.mkdtemp(prefix="ares-terminal-selftest-"))
    token = secrets.token_urlsafe(24)
    httpd, url = server.start(host="127.0.0.1", port=0, data_dir=str(d), access_token=token)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    checks = []

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)

    def get(path, cookie=""):
        req = urllib.request.Request(base + path, headers={"Cookie": cookie} if cookie else {})
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    status, _, body = get("/api/health")
    health = json.loads(body or b"{}")
    checks.append((f"health endpoint answers ({health.get('app')} {health.get('version')})",
                   status == 200 and health.get("app") == APP_NAME))
    checks.append(("version read from the bundled manifest", health.get("version") not in (None, "0.0.0")))
    checks.append(("the UI is refused without the token", get("/")[0] == 401))
    checks.append(("the API is refused without the token", get("/api/sessions")[0] == 401))
    status, headers, _ = get(f"/?{server.TOKEN_PARAM}={token}")
    cookie = (headers.get("Set-Cookie") or "").split(";")[0]
    checks.append(("the token is swapped for a cookie", status == 303 and token in cookie))
    status, _, body = get("/", cookie)
    checks.append(("the UI is served", status == 200 and b"ARES Terminal Console" in body))
    for asset in ("/app.js", "/style.css", "/vendor/xterm/xterm.min.js",
                  "/vendor/xterm/xterm-addon-fit.min.js"):
        checks.append((f"bundled {asset}", get(asset, cookie)[0] == 200))

    from app import pty_session
    checks.append((f"a terminal backend is available ({'ConPTY' if sys.platform == 'win32' else 'pty'})",
                   pty_session.supported()))
    if pty_session.supported():
        cmd = "cmd.exe /c echo ares-self-test-ok" if sys.platform == "win32" \
            else "/bin/sh -c 'echo ares-self-test-ok'"
        out = b""
        try:
            s = server.REGISTRY.create(command=cmd, cols=80, rows=24, cwd=str(d))
            deadline = time.time() + 20
            while time.time() < deadline and b"ares-self-test-ok" not in out:
                time.sleep(0.2)
                out = s.scrollback()
        except Exception as e:
            out = repr(e).encode()
        checks.append(("a shell runs in a terminal and its output comes back",
                       b"ares-self-test-ok" in out))

    if getattr(sys, "frozen", False) and sys.platform.startswith("linux"):
        bundle = os.path.dirname(sys.executable)
        checks.append(("shells started here use the system's libraries",
                       bundle not in os.environ.get("LD_LIBRARY_PATH", "")))

    server.REGISTRY.close_all()
    httpd.shutdown()
    httpd.server_close()
    shutil.rmtree(d, ignore_errors=True)
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(ok for _, ok in checks)
    print(f"{passed}/{len(checks)} checks passed")
    return 0 if passed == len(checks) else 1


def main() -> None:
    p = argparse.ArgumentParser(prog=APP_ID, description=APP_NAME)
    p.add_argument("--self-test", action="store_true",
                   help="start on a temporary data folder, check the bundle, exit")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {server.APP_VERSION}")
    p.add_argument("--data-dir", help="use this data folder instead of the per-user one")
    args, _ = p.parse_known_args()   # macOS passes -psn_... to a launched .app
    host_environment()
    if args.data_dir:
        os.environ["ARES_DATA_DIR"] = args.data_dir
    code = self_test() if args.self_test else run()
    sys.stdout.flush()
    sys.stderr.flush()
    # Daemon threads blocked on a PTY read must not keep a windowless app alive.
    os._exit(code)


if __name__ == "__main__":
    main()
