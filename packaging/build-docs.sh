#!/usr/bin/env bash
# Builds the documents uploaded to the ARES Application Suite into dist/docs/:
#   summary       EXECUTIVE-SUMMARY.md                     -> ares-terminal-console-executive-summary.pdf
#   presentation  packaging/docs/presentation.js           -> ares-terminal-console-executive-presentation.pptx
#                 executive-presentation.html (16:9)       -> ares-terminal-console-executive-presentation.pdf
#   architecture  ARCHITECTURE.md + blueprint.html         -> ares-terminal-console-architecture-and-blueprint.pdf
#   description   DESCRIPTION.md                           -> ares-terminal-console-description.pdf
# Needs: python3 with the "markdown" package, chromium (or google-chrome), pdfunite (poppler),
# node (the PowerPoint; `npm ci` in packaging/docs is run for you when node_modules is missing).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/docs"
WORK="$(mktemp -d)"
BUILT=()
trap 'rm -rf "$WORK" "${BUILT[@]}"' EXIT
mkdir -p "$OUT"

CHROME="$(command -v chromium || command -v chromium-browser || command -v google-chrome-stable || command -v google-chrome || true)"
[ -n "$CHROME" ] || { echo "chromium or google-chrome is needed to print the PDFs" >&2; exit 1; }
pdf() { # $1 input file, $2 output pdf
  "$CHROME" --headless=new --no-sandbox --disable-gpu --no-pdf-header-footer \
    --virtual-time-budget=8000 --print-to-pdf="$2" "file://$1" 2>/dev/null
  test -s "$2"
}

# Markdown -> printable HTML next to docs/ so ../app/static/brand paths resolve.
md2html() { # $1 markdown, $2 html
  python3 - "$1" "$2" <<'PY'
import sys, markdown, pathlib
src, dst = sys.argv[1], sys.argv[2]
body = markdown.markdown(pathlib.Path(src).read_text(encoding="utf-8"), extensions=["tables", "fenced_code", "sane_lists"])
css = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "Segoe UI", Inter, "Helvetica Neue", Arial, sans-serif; color: #0b1322; font-size: 10.5pt; line-height: 1.5; }
h1 { font-size: 22pt; color: #0b1322; border-bottom: 3px solid #22d3ee; padding-bottom: 6px; }
h2 { font-size: 15pt; color: #7a2fd0; margin-top: 22px; break-after: avoid; }
h3 { font-size: 12pt; color: #0b1322; break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; break-inside: avoid; }
th, td { border: 1px solid #cfd9e8; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #eef3fb; }
code { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; font-size: 9pt; background: #eef3fb; padding: 1px 4px; border-radius: 3px; }
pre { background: #eef3fb; padding: 10px; border-radius: 6px; font-size: 8pt; line-height: 1.25; overflow: hidden; break-inside: avoid; }
pre code { background: none; padding: 0; }
blockquote { border-left: 4px solid #22d3ee; margin: 8px 0; padding: 4px 12px; color: #4a5d80; }
a { color: #0e7490; }
img { max-width: 100%; }
"""
html = f'<!doctype html><html><head><meta charset="utf-8"><style>{css}</style></head><body>{body}</body></html>'
pathlib.Path(dst).write_text(html, encoding="utf-8")
PY
}

cd "$ROOT/docs"
for name in summary architecture description; do BUILT+=("$ROOT/docs/.build-$name.html"); done
md2html EXECUTIVE-SUMMARY.md .build-summary.html
md2html ARCHITECTURE.md .build-architecture.html
md2html DESCRIPTION.md .build-description.html

pdf "$ROOT/docs/.build-summary.html" "$OUT/ares-terminal-console-executive-summary.pdf"
pdf "$ROOT/docs/.build-description.html" "$OUT/ares-terminal-console-description.pdf"
pdf "$ROOT/docs/executive-presentation.html" "$OUT/ares-terminal-console-executive-presentation.pdf"
pdf "$ROOT/docs/.build-architecture.html" "$WORK/architecture.pdf"
pdf "$ROOT/docs/blueprint.html" "$WORK/blueprint.pdf"
pdfunite "$WORK/architecture.pdf" "$WORK/blueprint.pdf" "$OUT/ares-terminal-console-architecture-and-blueprint.pdf"

# The PowerPoint, from the same slides, with the speaker notes.
if [ ! -d "$ROOT/packaging/docs/node_modules" ]; then
  (cd "$ROOT/packaging/docs" && npm ci --no-audit --no-fund >/dev/null)
fi
node "$ROOT/packaging/docs/presentation.js" "$OUT/ares-terminal-console-executive-presentation.pptx" >/dev/null

ls -la "$OUT"
