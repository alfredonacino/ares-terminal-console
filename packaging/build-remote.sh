#!/usr/bin/env bash
# Build the Windows and macOS installers on their build hosts, from the committed
# tree (git archive HEAD), and copy the results into dist/ with merged SHA256SUMS.
#
#   packaging/build-remote.sh              both hosts
#   packaging/build-remote.sh windows      one of them
#
# PyInstaller does not cross-compile, so each platform builds on its own kind of
# machine. Hosts: ARES_WIN_HOST and ARES_MAC_HOST (user@host), set in your shell or in
# the git-ignored packaging/.build-hosts.env -- never in a tracked file. Each build gets a
# fresh virtualenv and must pass the frozen self-test, or nothing is copied back.
# CI (.github/workflows/release.yml) builds the same installers without any of this.
set -euo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
[ -f "$_here/.build-hosts.env" ] && . "$_here/.build-hosts.env"
WIN_HOST="${ARES_WIN_HOST:-}"
WIN_ROOT='C:\ares-build'
MAC_HOST="${ARES_MAC_HOST:-}"
MAC_ROOT='ares-build'
MAC_PYTHON="${ARES_MAC_PYTHON:-/opt/homebrew/opt/python@3.13/bin/python3.13}"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
SCP=(scp -q -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP=ares-terminal-console
VERSION="$(cat "$ROOT/VERSION")"
TAG="$APP-$VERSION"
LOGS="$ROOT/build/remote-$VERSION"
PLATFORMS="${*:-windows macos}"
DIST="$ROOT/dist/desktop"
mkdir -p "$LOGS" "$DIST"
for p in $PLATFORMS; do
  case "$p" in
    windows) [ -n "$WIN_HOST" ] || { echo "set ARES_WIN_HOST=user@host (or use CI)" >&2; exit 2; } ;;
    macos)   [ -n "$MAC_HOST" ] || { echo "set ARES_MAC_HOST=user@host (or use CI)" >&2; exit 2; } ;;
  esac
done

[ -z "$(git -C "$ROOT" status --porcelain -- app packaging apexmodule.toml VERSION ares.app.json requirements-desktop.txt)" ] \
  || echo "note: uncommitted changes are NOT in this build; it is built from HEAD"
TARBALL="$LOGS/src.tar.gz"
git -C "$ROOT" archive --format=tar.gz -o "$TARBALL" HEAD

pids=()
for p in $PLATFORMS; do
  case "$p" in
    windows)
      BAT="$LOGS/win.bat"
      printf '%s\r\n' '@echo off' "if not exist $WIN_ROOT mkdir $WIN_ROOT" "cd /d $WIN_ROOT" \
        "rmdir /s /q $TAG 2>nul" "mkdir $TAG" "tar -xzf $TAG.tar.gz -C $TAG" "cd $TAG" \
        'set "PATH=C:\Program Files (x86)\Inno Setup 6;%PATH%"' \
        "python packaging\\build.py --formats zip,inno,msi > $WIN_ROOT\\$TAG.log 2>&1" \
        "echo BUILD_EXIT=%ERRORLEVEL% >> $WIN_ROOT\\$TAG.log" > "$BAT"
      "${SSH[@]}" "$WIN_HOST" "if not exist $WIN_ROOT mkdir $WIN_ROOT" >/dev/null
      "${SCP[@]}" "$TARBALL" "$WIN_HOST:C:/ares-build/$TAG.tar.gz"
      "${SCP[@]}" "$BAT" "$WIN_HOST:C:/ares-build/$TAG.bat"
      ( "${SSH[@]}" "$WIN_HOST" "C:\\ares-build\\$TAG.bat" >/dev/null 2>&1 || true
        "${SSH[@]}" "$WIN_HOST" "type C:\\ares-build\\$TAG.log" > "$LOGS/windows.log" 2>&1 ) &
      pids+=($!) ;;
    macos)
      "${SSH[@]}" "$MAC_HOST" "mkdir -p ~/$MAC_ROOT"
      "${SCP[@]}" "$TARBALL" "$MAC_HOST:$MAC_ROOT/$TAG.tar.gz"
      "${SSH[@]}" "$MAC_HOST" "cd ~/$MAC_ROOT && rm -rf $TAG && mkdir $TAG && tar -xzf $TAG.tar.gz -C $TAG \
          && cd $TAG && export PATH=/opt/homebrew/bin:\$PATH && $MAC_PYTHON packaging/build.py; echo BUILD_EXIT=\$?" \
          > "$LOGS/macos.log" 2>&1 &
      pids+=($!) ;;
    *) echo "unknown platform $p" >&2; exit 2 ;;
  esac
done
echo "building $VERSION on: $PLATFORMS (logs in $LOGS)"
for pid in "${pids[@]}"; do wait "$pid" || true; done

failed=""
for p in $PLATFORMS; do
  log="$LOGS/$p.log"
  if grep -q "BUILD_EXIT=0" "$log" && grep -qE "[0-9]+/[0-9]+ checks passed" "$log"; then
    echo "  ok    $p: $(grep -oE '[0-9]+/[0-9]+ checks passed' "$log" | tail -n1)"
  else
    failed="$failed $p"; echo "  FAIL  $p:"; tail -n 30 "$log" | sed 's/^/        /'
  fi
done
[ -z "$failed" ] || { echo "build failed on:$failed"; exit 1; }

for p in $PLATFORMS; do
  mkdir -p "$LOGS/$p-dist"
  if [ "$p" = windows ]; then "${SCP[@]}" "$WIN_HOST:C:/ares-build/$TAG/dist/desktop/*" "$LOGS/$p-dist/"
  else "${SCP[@]}" "$MAC_HOST:$MAC_ROOT/$TAG/dist/desktop/*" "$LOGS/$p-dist/"; fi
  ( cd "$LOGS/$p-dist" && tr -d '\r' < SHA256SUMS | sed 's/ \*/  /' | sha256sum -c --quiet - ) \
    || { echo "the $p artefacts do not match their checksums"; exit 1; }
  cp "$LOGS/$p-dist/"*"$VERSION"* "$DIST/"
done
# Merge every SHA256SUMS that names this version into dist/desktop/SHA256SUMS.
cat "$DIST/SHA256SUMS" "$LOGS"/*-dist/SHA256SUMS 2>/dev/null | tr -d '\r' | sed 's/ \*/  /' \
  | awk 'NF==2 {sums[$2]=$0} END {for (f in sums) print sums[f]}' | sort -k2 \
  | while read -r sum name; do [ -f "$DIST/$name" ] && printf '%s  %s\n' "$sum" "$name"; done \
  > "$LOGS/SHA256SUMS.merged"   # only files still in dist/: an old version's entries go
cp "$LOGS/SHA256SUMS.merged" "$DIST/SHA256SUMS"
(cd "$DIST" && sha256sum -c --quiet SHA256SUMS) || { echo "dist/desktop/SHA256SUMS does not verify"; exit 1; }
echo "dist/desktop checksums verified"
ls -1 "$DIST" | grep "$VERSION"
