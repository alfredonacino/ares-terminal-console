#!/usr/bin/env bash
# Registers ARES Terminal Console in the ARES Application Suite and uploads its
# four documents (built by packaging/build-docs.sh), through the suite's integration API.
#
#   ARES_SUITE_TOKEN=asx_... packaging/register-ares-suite.sh
#   packaging/register-ares-suite.sh --dry-run      # show what would be sent
#
# The token is an integration token from Suite Admin -> Integrations. It is read
# from ARES_SUITE_TOKEN, or from ~/.config/ares-suite/token, and never printed.
# ARES_SUITE_URL selects another suite (default https://ares-suite.nacino.net).
#
# Safe to re-run: the application is matched by its integration key and updated
# in place, and each document replaces the one in its slot. Run it after each
# release so the version and the documents on the suite stay current.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="${ARES_SUITE_URL:-https://ares-suite.nacino.net}"
SUITE="${SUITE%/}"
KEY="ares-terminal-console"
PROD_URL="https://aresrepo.cybercontrol.tech"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

VERSION="$(sed -n 's/^version *= *"\(.*\)".*/\1/p' "$ROOT/apexmodule.toml" | head -1)"
[ -n "$VERSION" ] || { echo "no version in apexmodule.toml" >&2; exit 1; }

# Built by packaging/build-docs.sh (run below), as for ARES Karaoke Organizer:
# PDFs, and the presentation as PowerPoint.
DIST="$ROOT/dist/docs"
DOCS=(
  "summary      ares-terminal-console-executive-summary.pdf"
  "presentation ares-terminal-console-executive-presentation.pptx"
  "architecture ares-terminal-console-architecture-and-blueprint.pdf"
  "description  ares-terminal-console-description.pdf"
)

body="$(python3 - "$PROD_URL" "$VERSION" <<'PY'
import json, sys
prod, version = sys.argv[1:]
print(json.dumps({
    "name": "ARES Terminal Console",
    "url": prod,
    "category": "Operations",
    "icon": "💻",
    "description": (
        f"Split-pane terminal for server work (v{version}): tabs, broadcast, sessions that "
        "survive a closed window, and a record of every connection and command. Seven "
        "read-only server tools on any SSH pane (health, performance, logs, AI log analysis, "
        "packages, vulnerability scan, history) and an AI assistant that suggests commands "
        "but never runs them. Desktop app for Linux, macOS and Windows, Docker image, "
        "ApexBuild module. Downloads on ARES Repository."
    ),
    "tags": ["terminal", "ssh", "tmux", "operations", "desktop", "docker", "ai"],
    "isPublished": True,
}))
PY
)"

if [ "$DRY" = 1 ]; then
  echo "dry run: $SUITE, key $KEY, version $VERSION"
  echo "PUT /api/integration/apps/$KEY"
  echo "$body" | python3 -m json.tool
  for d in "${DOCS[@]}"; do read -r kind file <<<"$d"; echo "PUT /api/integration/apps/$KEY/documents/$kind  <- dist/docs/$file"; done
  exit 0
fi

TOKEN="${ARES_SUITE_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -r "$HOME/.config/ares-suite/token" ]; then
  TOKEN="$(tr -d '[:space:]' < "$HOME/.config/ares-suite/token")"
fi
[ -n "$TOKEN" ] || { echo "Set ARES_SUITE_TOKEN to an integration token from Suite Admin -> Integrations" >&2; exit 1; }

# The header goes through a file descriptor, so the token is not on curl's command line.
call() { # method path [curl args...]; prints the body, fails on HTTP >= 400
  local method="$1" path="$2"; shift 2
  local out code
  out="$(curl -sS -X "$method" -H @<(printf 'Authorization: Bearer %s\n' "$TOKEN") \
         -w $'\n%{http_code}' "$SUITE$path" "$@")"
  code="${out##*$'\n'}"; out="${out%$'\n'*}"
  echo "$out"
  [ "$code" -lt 400 ] || { echo "HTTP $code from $method $path" >&2; exit 1; }
}

echo "== Token"
call GET /api/integration/whoami

echo "== Application ($KEY, v$VERSION)"
call PUT "/api/integration/apps/$KEY" -H 'Content-Type: application/json' --data-binary "$body"

echo "== Documents"
"$ROOT/packaging/build-docs.sh" >/dev/null
for d in "${DOCS[@]}"; do
  read -r kind file <<<"$d"
  [ -s "$DIST/$file" ] || { echo "not built: $DIST/$file" >&2; exit 1; }
  call PUT "/api/integration/apps/$KEY/documents/$kind" \
    -H 'Content-Type: application/octet-stream' -H "X-File-Name: $file" \
    --data-binary @"$DIST/$file"
done
echo "== Done: $SUITE"
