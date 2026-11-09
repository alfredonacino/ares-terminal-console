#!/usr/bin/env bash
# Publish the installers in dist/ to ARES Repository.
#
#   packaging/release.sh [--stage] [--channel NAME] [--rollout PCT] [--notes TEXT] [--dry-run]
#
# Build first (packaging/build-linux.sh, packaging/build-arch.sh, and packaging/build-remote.sh for
# Windows and macOS, which copies their dist/ files here). Credentials come from
# ~/.config/ares-repository/ares-terminal-console.env (APEX_SERVER, APEX_APP, APEX_TOKEN,
# APEX_SIGNING_KEY_FILE), written by "ARES Repository/tools/issue-release-tokens.sh".
# Re-running is safe: an existing release is added to rather than recreated.
set -euo pipefail

SLUG=ares-terminal-console
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
VERSION="$(sed -n 's/^version *= *"\(.*\)".*/\1/p' "$ROOT/apexmodule.toml")"
ARES_DIR="${ARES_REPOSITORY_DIR:-/media/RAID1/CLAUDE_PROJECTS/ARES Repository}"
APEXCTL="${APEXCTL:-$ARES_DIR/cli/apexctl}"
ENV_FILE="${ARES_ENV_FILE:-$HOME/.config/ares-repository/$SLUG.env}"

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

PUBLISH=1 CHANNEL=stable ROLLOUT="" NOTES="" DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --stage) PUBLISH=0 ;;
    --channel) CHANNEL="${2:?}"; shift ;;
    --rollout) ROLLOUT="${2:?}"; shift ;;
    --notes) NOTES="${2?}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
  shift
done

FILES=()
for f in "$SLUG-$VERSION-linux-x86_64.tar.gz" "${SLUG}_${VERSION}_amd64.deb" "$SLUG-$VERSION-1-x86_64.pkg.tar.zst" \
         "$SLUG-$VERSION-windows-x86_64-setup.exe" "$SLUG-$VERSION-windows-x86_64.zip" \
         "$SLUG-$VERSION-macos-arm64.dmg" "$SLUG-$VERSION-macos-arm64.zip"; do
  if [ -f "$DIST/$f" ]; then FILES+=("$DIST/$f"); echo "    take  $f"; else echo "    skip  $f (not in dist/)"; fi
done
[ ${#FILES[@]} -gt 0 ] || die "nothing to publish in dist/ for $VERSION"

# Each file must match SHA256SUMS, so a half-copied file is never published.
(cd "$DIST" && for f in "${FILES[@]}"; do grep "  $(basename "$f")\$" SHA256SUMS; done | sha256sum -c --quiet) \
  || die "dist/SHA256SUMS does not match the files"

if [ -z "$NOTES" ]; then
  NOTES="$(awk -v v="## [$VERSION]" '$0==v{on=1;next} /^## \[/{on=0} on' "$ROOT/CHANGELOG.md" | sed '/^$/d')"
  NOTES="${NOTES:-Release $VERSION}"
fi

if [ -f "$ENV_FILE" ]; then set -a; . "$ENV_FILE"; set +a; fi
ARGS=(push "${APEX_APP:-$SLUG}" "$VERSION" "${FILES[@]}" --channel "$CHANNEL" --notes "$NOTES")
[ -n "$ROLLOUT" ] && ARGS+=(--rollout "$ROLLOUT")
[ "$PUBLISH" = 1 ] && ARGS+=(--publish)

if [ "$DRY_RUN" = 1 ]; then
  say "dry run: $APEX_SERVER app ${APEX_APP:-$SLUG} $VERSION channel $CHANNEL, ${#FILES[@]} files, $([ $PUBLISH = 1 ] && echo publish || echo stage)"
  say "token $([ -n "${APEX_TOKEN:-}" ] && echo set || echo MISSING), signing key $([ -r "${APEX_SIGNING_KEY_FILE:-/nonexistent}" ] && echo found || echo MISSING)"
  printf '%s\n' "$NOTES" | sed 's/^/    /'
  exit 0
fi

[ -n "${APEX_TOKEN:-}" ] || die "APEX_TOKEN missing: run \"$ARES_DIR/tools/issue-release-tokens.sh\" $SLUG"
if [ -z "${APEX_SIGNING_KEY:-}" ]; then
  [ -r "${APEX_SIGNING_KEY_FILE:-}" ] || die "no signing key (APEX_SIGNING_KEY or APEX_SIGNING_KEY_FILE in $ENV_FILE)"
  APEX_SIGNING_KEY="$(tr -d '[:space:]' < "$APEX_SIGNING_KEY_FILE")"
fi
export APEX_SERVER APEX_TOKEN APEX_SIGNING_KEY   # apexctl reads the key from the environment, never argv
say "publishing $VERSION to $APEX_SERVER"
"$APEXCTL" "${ARGS[@]}"
