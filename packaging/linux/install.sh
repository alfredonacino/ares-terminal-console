#!/bin/sh
# Install ARES Terminal Console for the current user (no root needed).
#   ./install.sh            install or update into ~/.local/opt/ares-terminal-console
#   ./install.sh --remove   uninstall (your data in ~/.local/share/ares-terminal-console is kept)
set -e
APP=ares-terminal-console
HERE=$(cd "$(dirname "$0")" && pwd)
DEST="$HOME/.local/opt/$APP"
mkdir -p "$HOME/.local/opt"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/512x512/apps"
BIN="$HOME/.local/bin"

if [ "$1" = "--remove" ]; then
  rm -rf "$DEST" "$APPS/$APP.desktop" "$ICONS/$APP.png" "$BIN/$APP"
  echo "Removed. Your data is still in ${XDG_DATA_HOME:-$HOME/.local/share}/$APP"
  exit 0
fi
rm -rf "$DEST.new" && cp -a "$HERE/$APP" "$DEST.new" && rm -rf "$DEST" && mv "$DEST.new" "$DEST"
mkdir -p "$APPS" "$ICONS" "$BIN"
cp "$HERE/$APP.png" "$ICONS/$APP.png"
sed "s|@EXEC@|$DEST/$APP|" "$HERE/$APP.desktop" > "$APPS/$APP.desktop"
ln -sf "$DEST/$APP" "$BIN/$APP"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" >/dev/null 2>&1 || true
echo "Installed to $DEST"
echo "Start it from your applications menu (ARES Terminal Console) or run: $APP"
