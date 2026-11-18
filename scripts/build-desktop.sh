#!/usr/bin/env bash
# ARES Suite desktop build for ares-terminal-console, for THIS host OS.
# CI (.github/workflows/release.yml) runs it on Linux, Windows and macOS; `suite build desktop` runs it here.
#
# It drives the app's own packaging (packaging/build.py, PyInstaller one-folder build that must pass
# its frozen self-test) and writes, into dist/desktop/:
#   linux    <key>-<v>-linux-<arch>.{deb,rpm,pkg.tar.zst,AppImage,tar.gz}
#   windows  <key>-<v>-windows-<arch>-setup.exe (Inno Setup, per user), .msi (WiX 5, per machine), .zip
#   macos    <key>-<v>-macos-<arch>.{dmg,zip}
# The desktop app has no sign-in: it is one person's terminal on their own computer.
#
# Linux: the freeze runs in a Debian 11 container (packaging/build-linux.sh) when Docker is available, so
# the result runs on older distributions; rpm, Arch and AppImage repackage that same tree with nfpm and
# appimagetool (downloaded into build/tools when missing). Set ARES_NATIVE_BUILD=1 to freeze on the host.
set -euo pipefail
cd "$(dirname "$0")/.."
export APP_VERSION="${APP_VERSION:-$(cat VERSION)}"
NFPM_VERSION=2.41.1
TOOLS="$PWD/build/tools"; mkdir -p "$TOOLS" dist/desktop
PY="${PYTHON:-$(command -v python3 || command -v python)}"

case "$(uname -s)" in
  Linux)
    if [ "${ARES_NATIVE_BUILD:-0}" != 1 ] && command -v docker >/dev/null && docker info >/dev/null 2>&1; then
      packaging/build-linux.sh --formats tar,deb
    else
      "$PY" packaging/build.py --formats tar,deb
    fi
    export PATH="$TOOLS:$PATH"
    if ! command -v nfpm >/dev/null; then
      curl -fsSL "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz" \
        | tar -xz -C "$TOOLS" nfpm
    fi
    if ! command -v appimagetool >/dev/null; then
      curl -fsSL -o "$TOOLS/appimagetool" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
      chmod +x "$TOOLS/appimagetool"
    fi
    # The tree already passed its self-test inside the builder; this only repackages it.
    "$PY" packaging/build.py --skip-freeze --no-self-test --formats rpm,arch,appimage ;;
  Darwin)
    "$PY" packaging/build.py --formats dmg,zip ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    "$PY" packaging/build.py --formats zip,inno,msi ;;
  *) echo "unsupported build host: $(uname -s)" >&2; exit 2 ;;
esac

# Never a .pacman file: Arch packages are .pkg.tar.zst.
find dist/desktop -maxdepth 1 -name '*.pacman' -delete
ls -1 dist/desktop | grep -F -- "-$APP_VERSION-" || { echo "no installers for $APP_VERSION in dist/desktop" >&2; exit 1; }
