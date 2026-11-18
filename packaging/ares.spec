# PyInstaller spec for the ARES Terminal Console desktop app.
#   pyinstaller --noconfirm --distpath build/dist --workpath build/work packaging/ares.spec
# Produces one folder with two programs sharing the same libraries:
#   ares-terminal-console      the app (windowed on Windows and macOS)
#   ares-terminal-console-cli  the same with a console, for --self-test and logs
import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
APP_ID = "ares-terminal-console"
ICON = str(ROOT / "packaging" / "icons" / ("ares.ico" if sys.platform == "win32" else "ares.icns"))
VERSION = (ROOT / "VERSION").read_text().strip()   # the one place the version lives

hidden = collect_submodules("app") + collect_submodules("claude_agent_sdk")
# Not collect_data_files("claude_agent_sdk"): that would carry its _bundled CLI, 200+ MB per platform.
# The assistant drives the Claude Code the user installed and signed in to.
datas = [(str(ROOT / "app" / "static"), "app/static"), (str(ROOT / "apexmodule.toml"), "."), (str(ROOT / "VERSION"), "."),
         (str(ROOT / "ares.app.json"), "."),
         (str(ROOT / "packaging" / "icons" / "ares.png"), "icons"),
         (str(ROOT / "LICENSE"), ".")]
if sys.platform in ("win32", "darwin"):
    hidden += collect_submodules("webview")
    datas += collect_data_files("webview")
if sys.platform == "win32":
    hidden += collect_submodules("winpty")
    datas += collect_data_files("winpty")
excludes = ["tkinter", "test", "unittest", "pytest", "IPython", "matplotlib", "numpy", "PyQt5", "PyQt6"]
if sys.platform.startswith("linux"):
    # The window is Qt (app/desktop.py imports it lazily, so name it here). Only the modules it
    # uses: QtWebEngine brings QtQml/QtQuick/QtWebChannel along, the rest of PySide6 stays out.
    hidden += ["PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets", "PySide6.QtNetwork",
               "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets"]
    excludes += ["webview", "gi"] + [f"PySide6.{m}" for m in (
        "Qt3DAnimation", "Qt3DCore", "Qt3DExtras", "Qt3DInput", "Qt3DLogic", "Qt3DRender", "QtBluetooth",
        "QtCharts", "QtDataVisualization", "QtGraphs", "QtDesigner", "QtHelp", "QtMultimedia",
        "QtMultimediaWidgets", "QtNfc", "QtPdf", "QtPdfWidgets", "QtPositioning", "QtQuick3D",
        "QtRemoteObjects", "QtScxml", "QtSensors", "QtSerialBus", "QtSerialPort", "QtSpatialAudio",
        "QtSql", "QtStateMachine", "QtTest", "QtTextToSpeech", "QtWebEngineQuick", "QtWebSockets",
        "QtWebView", "QtXml", "QtHttpServer", "QtLocation", "QtSvgWidgets", "QtUiTools")]
else:
    excludes += ["PySide6"]

a = Analysis([str(ROOT / "packaging" / "entry.py")], pathex=[str(ROOT)], hiddenimports=hidden, datas=datas,
             excludes=excludes, noarchive=False)
if sys.platform.startswith("linux"):
    # The desktop belongs to the machine the app runs on. The builder's copies of these (Debian 11) are
    # older than the host's, and Mesa's EGL and GBM -- loaded from the host -- then fail against them: no
    # EGL, a crashed window (libgbm is also too old for Qt WebEngine, which needs Mesa 21.1). A bundled
    # libnss3 next to the system's NSS modules is a version mismatch too. The packages depend on these.
    _system = ("libstdc++.so", "libgcc_s.so", "libz.so", "libzstd.so", "libffi.so", "libexpat.so",
               "libgbm.so", "libdrm.so", "libfontconfig.so", "libfreetype.so", "libpng16.so", "libasound.so",
               "libnss3.so", "libnssutil3.so", "libsmime3.so", "libnspr4.so", "libplc4.so", "libplds4.so",
               "libglib-2.0.so", "libgio-2.0.so", "libgobject-2.0.so", "libgmodule-2.0.so",
               "libgthread-2.0.so", "libpcre.so", "libpcre2-8.so", "libdbus-1.so", "libsystemd.so",
               "libmount.so", "libblkid.so", "libselinux.so", "libuuid.so", "libgcrypt.so", "libgpg-error.so",
               "liblz4.so", "libbsd.so", "libmd.so", "libX", "libxcb", "libxkb", "libxshmfence.so",
               "libwayland-")
    a.binaries = [b for b in a.binaries if not Path(b[0]).name.startswith(_system)]
pyz = PYZ(a.pure)

gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name=APP_ID, console=sys.platform.startswith("linux"),
          icon=ICON, disable_windowed_traceback=False, upx=False)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name=f"{APP_ID}-cli", console=True, icon=ICON, upx=False)
coll = COLLECT(gui, cli, a.binaries, a.datas, name=APP_ID, upx=False)

if sys.platform == "darwin":
    app = BUNDLE(coll, name="ARES Terminal Console.app", icon=ICON,
                 bundle_identifier="tech.cybercontrol.ares-terminal-console", version=VERSION,
                 info_plist={"CFBundleShortVersionString": VERSION, "CFBundleVersion": VERSION,
                             "CFBundleDisplayName": "ARES Terminal Console",
                             "NSHighResolutionCapable": True, "LSMinimumSystemVersion": "11.0",
                             "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True}})
