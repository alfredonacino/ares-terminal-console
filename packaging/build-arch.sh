#!/bin/sh
# Build the Arch Linux package (pacman .pkg.tar.zst) from the Linux tarball that
# packaging/build-linux.sh produced. Needs makepkg (Arch, Manjaro, EndeavourOS, CachyOS...).
#   packaging/build-arch.sh         ->  dist/ares-terminal-console-<version>-1-x86_64.pkg.tar.zst
# Install it with: sudo pacman -U dist/ares-terminal-console-<version>-1-x86_64.pkg.tar.zst
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP=ares-terminal-console
VERSION=$(sed -n 's/^version *= *"\(.*\)".*/\1/p' "$ROOT/apexmodule.toml")
TARBALL="$ROOT/dist/$APP-$VERSION-linux-x86_64.tar.gz"
[ -f "$TARBALL" ] || { echo "$TARBALL is missing: run packaging/build-linux.sh first" >&2; exit 1; }
command -v makepkg >/dev/null || { echo "makepkg not found: run this on Arch Linux" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SUM=$(sha256sum "$TARBALL" | cut -d' ' -f1)
LSUM=$(sha256sum "$ROOT/LICENSE" | cut -d' ' -f1)
sed -e "s/@VERSION@/$VERSION/" -e "s/@SHA256@/$SUM/" -e "s/@LICENSE_SHA256@/$LSUM/" \
  "$ROOT/packaging/arch/PKGBUILD" > "$WORK/PKGBUILD"
cp "$ROOT/LICENSE" "$WORK/"
ln -s "$TARBALL" "$WORK/"
(cd "$WORK" && PKGDEST="$WORK/out" PKGEXT=.pkg.tar.zst makepkg --force --cleanbuild --nodeps --noconfirm >&2 \
   && makepkg --printsrcinfo > .SRCINFO)
PKG=$(ls "$WORK"/out/*.pkg.tar.zst)
cp "$PKG" "$ROOT/dist/"
cp "$WORK/PKGBUILD" "$ROOT/dist/PKGBUILD"
cp "$WORK/.SRCINFO" "$ROOT/dist/.SRCINFO"
NAME=$(basename "$PKG")
cd "$ROOT/dist"
{ grep -v "  $NAME\$" SHA256SUMS 2>/dev/null || true; sha256sum "$NAME"; } | sort -k2 > SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS
echo "dist/$NAME"
