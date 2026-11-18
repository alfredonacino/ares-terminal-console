"""
ARES Terminal Console as a desktop application.

Runs the server on 127.0.0.1 on a free port, with an access token so that no
other user of the machine can open a shell through it, and shows it in a window:

* Windows and macOS: a native window (pywebview: WebView2 / WKWebView).
* Linux: a native Qt window (PySide6 + QtWebEngine), the toolkit ARES Ultimate
  Console is built on, with the app's own name and icon in the task bar. Run
  from source without PySide6, it falls back to an app window of Chrome,
  Chromium, Brave or Edge, and then to a tab of the default browser.

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


def _icon_path() -> str:
    for base in (getattr(sys, "_MEIPASS", None), Path(__file__).resolve().parent.parent / "packaging"):
        if base:
            f = Path(base) / "icons" / "ares.png"
            if f.is_file():
                return str(f)
    return ""


def _qt_window(url: str, d: Path, quit_event: threading.Event) -> bool:
    """A native Qt window around the console, as ARES Ultimate Console is a Qt
    application. False when PySide6 (with QtWebEngine) is not available."""
    try:
        from PySide6.QtCore import QTimer, QUrl
        from PySide6.QtGui import QColor, QDesktopServices, QIcon, QKeySequence, QShortcut
        from PySide6.QtWidgets import QApplication, QFileDialog
        from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings
        from PySide6.QtWebEngineWidgets import QWebEngineView
    except Exception:
        return False

    origin = QUrl(url)

    def ours(u) -> bool:
        return u.scheme() in ("data", "blob", "about") or (
            u.host() == origin.host() and u.port() == origin.port())

    class Page(QWebEnginePage):
        """Keeps the window on the console: any other address, and any link
        meant for a new window, goes to the user's own browser."""

        def acceptNavigationRequest(self, u, kind, is_main_frame):
            if is_main_frame and not ours(u):
                QDesktopServices.openUrl(u)
                return False
            return True

        def createWindow(self, _type):
            return _External(self.profile(), self)

    class _External(QWebEnginePage):
        def acceptNavigationRequest(self, u, kind, is_main_frame):
            if u.isValid() and not u.isEmpty():
                QDesktopServices.openUrl(u)
            self.deleteLater()
            return False

    # Chromium inside a frozen bundle: the GPU process can fail on some
    # drivers, which would leave a black window. Software is plenty for text.
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu-compositing")
    QApplication.setApplicationName(APP_NAME)
    QApplication.setApplicationDisplayName(APP_NAME)
    QApplication.setDesktopFileName(APP_ID)   # the Wayland app id, matches the .desktop entry
    app = QApplication.instance() or QApplication([sys.argv[0]])
    icon = _icon_path()
    if icon:
        app.setWindowIcon(QIcon(icon))

    store = d / "qtwebengine"
    store.mkdir(parents=True, exist_ok=True)
    profile = QWebEngineProfile(APP_ID, app)   # named: kept on disk, so a layout survives a restart
    profile.setPersistentStoragePath(str(store / "storage"))
    profile.setCachePath(str(store / "cache"))
    profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)

    def _download(item):
        path, _ = QFileDialog.getSaveFileName(view, "Save", str(Path.home() / item.downloadFileName()))
        if not path:
            item.cancel()
            return
        item.setDownloadDirectory(str(Path(path).parent))
        item.setDownloadFileName(Path(path).name)
        item.accept()
    profile.downloadRequested.connect(_download)

    view = QWebEngineView()
    page = Page(profile, view)
    page.setBackgroundColor(QColor("#0d1117"))
    st = page.settings()
    st.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, True)
    if hasattr(QWebEngineSettings, "JavascriptCanPaste"):
        st.setAttribute(QWebEngineSettings.JavascriptCanPaste, True)
    st.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
    view.setPage(page)
    view.setWindowTitle(APP_NAME)
    page.titleChanged.connect(lambda t: view.setWindowTitle(t or APP_NAME))
    view.resize(1280, 820)
    view.setMinimumSize(720, 480)
    QShortcut(QKeySequence("Ctrl+Shift+R"), view, activated=view.reload)
    QShortcut(QKeySequence("F11"), view,
              activated=lambda: view.showNormal() if view.isFullScreen() else view.showFullScreen())
    view.load(QUrl(url))
    view.show()

    # Wake the event loop now and then, so SIGTERM and Ctrl+C are noticed.
    timer = QTimer(view)
    timer.timeout.connect(lambda: app.quit() if quit_event.is_set() else None)
    timer.start(300)
    try:
        app.exec()
    except KeyboardInterrupt:
        pass
    finally:
        view.setPage(None)
        page.deleteLater()
        view.deleteLater()
    return True


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

    if sys.platform.startswith("linux") and os.environ.get("ARES_WINDOW") != "browser":
        if _qt_window(url, d, quit_event):
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
    httpd, url = server.start(host="127.0.0.1", port=0, data_dir=str(d), access_token=token, auth="local")
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
    httpd, url = server.start(host="127.0.0.1", port=0, data_dir=str(d), access_token=token, auth="local")
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

    # The assistant: the SDK must have arrived (it is imported lazily, which is
    # exactly the shape a freezer misses), and looking for Claude Code must work
    # whether or not this machine has it. Being signed in is the user's business.
    from app import agent
    try:
        import claude_agent_sdk  # noqa: F401
        sdk = True
    except Exception:
        sdk = False
    checks.append(("the assistant SDK is bundled", sdk))
    try:
        cli = agent.find_cli()
        checks.append((f"Claude Code lookup works ({cli or 'not installed here'})", True))
    except Exception as e:
        checks.append((f"Claude Code lookup works ({e!r})", False))

    if sys.platform.startswith("linux"):
        # That the window's modules and Chromium's helper arrived is what a
        # freezer can get wrong, so that must pass. Whether this machine's
        # graphics libraries can load Qt WebEngine is the machine's business
        # (a build container's are older than a desktop's), so that is only
        # reported: without it the app opens a browser window instead.
        try:
            from PySide6.QtCore import QLibraryInfo
            where = QLibraryInfo.LibraryPath
            found = (Path(QLibraryInfo.path(where.LibraryExecutablesPath)) / "QtWebEngineProcess").is_file() \
                and any(Path(QLibraryInfo.path(where.LibrariesPath)).glob("libQt6WebEngineCore.so*"))
        except Exception:
            found = False
        checks.append(("the Qt window is bundled (PySide6, Qt WebEngine, QtWebEngineProcess)", found))
        try:
            from PySide6 import QtWebEngineWidgets  # noqa: F401
            print("INFO  this machine can open the Qt window")
        except Exception as e:
            print(f"INFO  this machine cannot load Qt WebEngine ({e}); the app would open a browser window")

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
