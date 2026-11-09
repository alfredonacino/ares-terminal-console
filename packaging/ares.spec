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
VERSION = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "apexmodule.toml").read_text(), re.M).group(1)

hidden = collect_submodules("app")
datas = [(str(ROOT / "app" / "static"), "app/static"), (str(ROOT / "apexmodule.toml"), "."),
         (str(ROOT / "packaging" / "icons" / "ares.png"), "icons"),
         (str(ROOT / "LICENSE"), ".")]
if sys.platform in ("win32", "darwin"):
    hidden += collect_submodules("webview")
    datas += collect_data_files("webview")
if sys.platform == "win32":
    hidden += collect_submodules("winpty")
    datas += collect_data_files("winpty")
excludes = ["tkinter", "test", "unittest", "pytest", "IPython", "matplotlib", "numpy", "claude_agent_sdk"]
if sys.platform.startswith("linux"):
    excludes += ["webview", "gi", "PyQt5", "PyQt6", "PySide6"]

a = Analysis([str(ROOT / "packaging" / "entry.py")], pathex=[str(ROOT)], hiddenimports=hidden, datas=datas,
             excludes=excludes, noarchive=False)
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
