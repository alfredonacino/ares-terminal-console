"""Build the ARES Terminal Console desktop app for the platform this runs on.

    python packaging/build.py                     # freeze, self-test, package this platform's formats
    python packaging/build.py --formats tar       # only some formats
    python packaging/build.py --skip-freeze       # re-package the last frozen tree

Formats:
    Linux    tar (tar.gz with install.sh), deb
    Windows  zip, inno (setup .exe, needs Inno Setup 6)
    macOS    dmg (the .app in a disk image), zip (the .app zipped)

Linux builds should run in an old-glibc container so the result runs on older distributions:
    packaging/build-linux.sh

Everything lands in dist/, with SHA256SUMS.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
FROZEN = BUILD / "dist"
OUT = ROOT / "dist"
APP_ID = "ares-terminal-console"
APP_NAME = "ARES Terminal Console"
VERSION = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "apexmodule.toml").read_text(), re.M).group(1)
PLATFORM = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower(),
                                                                                       platform.machine().lower())
DEFAULT_FORMATS = {"linux": ["tar", "deb"], "windows": ["zip", "inno"], "macos": ["dmg", "zip"]}


def step(msg: str) -> None:
    print(f"\n==> {msg}", flush=True)


def run(cmd: list, **kw) -> None:
    print("   $", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def venv_python() -> Path:
    v = BUILD / "venv"
    py = v / ("Scripts/python.exe" if PLATFORM == "windows" else "bin/python")
    if not py.exists():
        step("creating the build virtualenv")
        run([sys.executable, "-m", "venv", v])
    run([py, "-m", "pip", "install", "-q", "--upgrade", "pip"])
    run([py, "-m", "pip", "install", "-q", "-r", ROOT / "requirements-desktop.txt"])
    return py


def freeze(py: Path) -> Path:
    step("freezing with PyInstaller")
    shutil.rmtree(FROZEN, ignore_errors=True)
    run([py, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN", "--distpath", FROZEN,
         "--workpath", BUILD / "work", ROOT / "packaging" / "ares.spec"], cwd=ROOT)
    return frozen_tree()


def frozen_tree() -> Path:
    return FROZEN / (f"{APP_NAME}.app" if PLATFORM == "macos" else APP_ID)


def cli_exe(tree: Path) -> Path:
    if PLATFORM == "macos":
        return tree / "Contents" / "MacOS" / f"{APP_ID}-cli"
    return tree / (f"{APP_ID}-cli.exe" if PLATFORM == "windows" else f"{APP_ID}-cli")


def self_test(tree: Path) -> None:
    step("self-test of the frozen app")
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARES_")}
    res = subprocess.run([str(cli_exe(tree)), "--self-test"], capture_output=True, text=True, env=env, timeout=180)
    lines = [l for l in res.stdout.splitlines() if l.startswith(("PASS", "FAIL")) or "checks passed" in l]
    print("\n".join("   " + l for l in lines))
    if res.returncode != 0:
        print(res.stdout[-3000:], res.stderr[-3000:], sep="\n")
        raise SystemExit("self-test failed")


def base_name() -> str:
    return f"{APP_ID}-{VERSION}-{PLATFORM}-{ARCH}"


# ------------------------------------------------------------------ formats
def build_tar(tree: Path) -> Path:
    stage = BUILD / "stage" / base_name()
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(tree, stage / APP_ID, symlinks=True)
    for f in ("install.sh", f"{APP_ID}.desktop"):
        shutil.copy2(ROOT / "packaging" / "linux" / f, stage / f)
    shutil.copy2(ROOT / "packaging" / "icons" / "ares.png", stage / f"{APP_ID}.png")
    (stage / "install.sh").chmod(0o755)
    out = OUT / f"{base_name()}.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        tar.add(stage, arcname=base_name())
    return out


def build_deb(tree: Path) -> Path:
    """A .deb is an ar archive of debian-binary, control.tar.gz and data.tar.gz, in that order."""
    root = BUILD / "stage" / "deb"
    shutil.rmtree(root, ignore_errors=True)
    opt = root / "opt" / APP_ID
    shutil.copytree(tree, opt, symlinks=True)
    (root / "usr/bin").mkdir(parents=True)
    os.symlink(f"/opt/{APP_ID}/{APP_ID}", root / "usr/bin" / APP_ID)
    apps = root / "usr/share/applications"
    apps.mkdir(parents=True)
    desktop = (ROOT / "packaging/linux" / f"{APP_ID}.desktop").read_text().replace("@EXEC@", f"/opt/{APP_ID}/{APP_ID}")
    (apps / f"{APP_ID}.desktop").write_text(desktop)
    for size, src in ((512, "ares.png"), (256, "ares-256.png")):
        d = root / f"usr/share/icons/hicolor/{size}x{size}/apps"
        d.mkdir(parents=True)
        shutil.copy2(ROOT / "packaging/icons" / src, d / f"{APP_ID}.png")
    size_kb = sum(f.stat().st_size for f in root.rglob("*") if f.is_file() and not f.is_symlink()) // 1024
    control = (f"Package: {APP_ID}\nVersion: {VERSION}\nSection: utils\nPriority: optional\n"
               f"Architecture: {'amd64' if ARCH == 'x86_64' else ARCH}\nInstalled-Size: {size_kb}\n"
               "Maintainer: ARES <alfredo@nacino.net>\nRecommends: chromium | google-chrome-stable | brave-browser\nSuggests: xdg-utils\n"
               f"Description: {APP_NAME}\n Split-pane terminals with broadcast, keep-alive, a connection history\n"
               " and a command assistant, in a desktop window.\n")
    work = BUILD / "stage" / "deb-ar"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    (work / "debian-binary").write_text("2.0\n")

    def owner_root(ti: tarfile.TarInfo) -> tarfile.TarInfo:
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        return ti

    ctl = work / "control"
    ctl.mkdir()
    (ctl / "control").write_text(control)
    with tarfile.open(work / "control.tar.gz", "w:gz") as t:
        t.add(ctl / "control", arcname="./control", filter=owner_root)
    with tarfile.open(work / "data.tar.gz", "w:gz") as t:
        for p in sorted(root.iterdir()):
            t.add(p, arcname=f"./{p.name}", filter=owner_root)
    out = OUT / f"{APP_ID}_{VERSION}_{'amd64' if ARCH == 'x86_64' else ARCH}.deb"
    out.unlink(missing_ok=True)
    _ar(out, [work / "debian-binary", work / "control.tar.gz", work / "data.tar.gz"])
    return out


def _ar(out: Path, members: list[Path]) -> None:
    with open(out, "wb") as fh:
        fh.write(b"!<arch>\n")
        for m in members:
            data = m.read_bytes()
            header = f"{m.name + '/':<16}{int(time.time()):<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n"
            fh.write(header.encode())
            fh.write(data)
            if len(data) % 2:
                fh.write(b"\n")


def build_zip(tree: Path) -> Path:
    out = OUT / f"{base_name()}.zip"
    out.unlink(missing_ok=True)
    if PLATFORM == "macos":    # ditto keeps the bundle's symlinks and permissions
        run(["ditto", "-c", "-k", "--keepParent", tree, out])
        return out
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(tree.rglob("*")):
            z.write(f, Path(APP_ID) / f.relative_to(tree))
    return out


def build_inno(tree: Path) -> Path:
    iscc = shutil.which("iscc") or r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if not Path(iscc).exists() and not shutil.which("iscc"):
        raise SystemExit("Inno Setup 6 (ISCC.exe) is not installed")
    run([iscc, "/Q", f"/DAppVersion={VERSION}", f"/DSourceDir={tree}", f"/DOutputDir={OUT}",
         f"/DOutputBase={APP_ID}-{VERSION}-windows-{ARCH}-setup", f"/DIconFile={ROOT / 'packaging/icons/ares.ico'}",
         ROOT / "packaging" / "windows" / "ares.iss"])
    return OUT / f"{APP_ID}-{VERSION}-windows-{ARCH}-setup.exe"


def build_dmg(tree: Path) -> Path:
    stage = BUILD / "stage" / "dmg"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    run(["ditto", tree, stage / tree.name])
    os.symlink("/Applications", stage / "Applications")
    out = OUT / f"{base_name()}.dmg"
    out.unlink(missing_ok=True)
    run(["hdiutil", "create", "-volname", f"{APP_NAME} {VERSION}", "-srcfolder", stage, "-ov", "-format", "UDZO", out])
    return out


BUILDERS = {"tar": build_tar, "deb": build_deb, "zip": build_zip, "inno": build_inno, "dmg": build_dmg}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--formats", help="comma separated; default: " + ",".join(DEFAULT_FORMATS[PLATFORM]))
    p.add_argument("--skip-freeze", action="store_true", help="package the existing build/dist tree")
    args = p.parse_args()
    formats = args.formats.split(",") if args.formats else DEFAULT_FORMATS[PLATFORM]
    print(f"{APP_NAME} {VERSION} for {PLATFORM}-{ARCH}: {', '.join(formats)}")
    tree = frozen_tree() if args.skip_freeze else freeze(venv_python())
    if not tree.exists():
        raise SystemExit(f"{tree} does not exist: run without --skip-freeze")
    self_test(tree)
    OUT.mkdir(exist_ok=True)
    built = []
    for f in formats:
        step(f"packaging {f}")
        built.append(BUILDERS[f](tree))
    sums = OUT / "SHA256SUMS"
    lines = {l.split()[-1]: l for l in (sums.read_text().splitlines() if sums.exists() else []) if l.strip()}
    for b in built:
        lines[b.name] = f"{hashlib.sha256(b.read_bytes()).hexdigest()}  {b.name}"
    sums.write_text("\n".join(lines[k] for k in sorted(lines)) + "\n")
    step("done")
    for b in built:
        print(f"   {b.relative_to(ROOT)}  ({b.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
