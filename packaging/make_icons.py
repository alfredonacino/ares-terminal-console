"""Render the ARES Terminal Console icon into every format the installers need.

    python packaging/make_icons.py

The drawing is app/static/brand/ares-terminal-icon.svg; this only rasterises it:

    packaging/icons/ares.png (512), ares-256.png, ares.ico, ares.icns
    app/static/icon.png (256, the page icon), app/static/brand/*.png

Needs rsvg-convert (librsvg) and Pillow, at icon-making time only; the app
itself needs neither.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "app" / "static" / "brand"
OUT = ROOT / "packaging" / "icons"


def render(svg: Path, png: Path, width: int, height: int = 0) -> None:
    args = ["rsvg-convert", "-w", str(width)] + (["-h", str(height)] if height else [])
    subprocess.run(args + [str(svg), "-o", str(png)], check=True)


def main() -> None:
    if not shutil.which("rsvg-convert"):
        raise SystemExit("rsvg-convert not found (install librsvg)")
    OUT.mkdir(exist_ok=True)
    icon = BRAND / "ares-terminal-icon.svg"
    with tempfile.TemporaryDirectory() as tmp:
        big = Path(tmp) / "icon-1024.png"
        render(icon, big, 1024, 1024)
        img = Image.open(big).convert("RGBA")
        img.resize((512, 512), Image.LANCZOS).save(OUT / "ares.png")
        img.resize((256, 256), Image.LANCZOS).save(OUT / "ares-256.png")
        img.resize((256, 256), Image.LANCZOS).save(ROOT / "app" / "static" / "icon.png")
        img.save(OUT / "ares.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
        img.save(OUT / "ares.icns")
    for size in (512, 192, 64):
        render(icon, BRAND / f"ares-terminal-icon-{size}.png", size, size)
    for variant in ("light", "dark"):
        render(BRAND / f"ares-terminal-logo-{variant}.svg", BRAND / f"ares-terminal-logo-{variant}.png", 880)
    print("wrote", ", ".join(sorted(p.name for p in OUT.iterdir())), "+ app/static/icon.png, app/static/brand/*.png")


if __name__ == "__main__":
    main()
