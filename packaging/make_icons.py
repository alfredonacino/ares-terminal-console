"""Draw the ARES Terminal Console icon and write every format the installers need.

    python packaging/make_icons.py      # packaging/icons/ares.{png,ico,icns}, ares-256.png

Needs Pillow, at icon-making time only; the app itself does not.
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent / "icons"
NAVY, PANEL, ACCENT, WHITE = (13, 17, 23), (22, 27, 34), (177, 76, 255), (236, 240, 246)


def draw(size: int = 1024) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 1024
    d.rounded_rectangle([40 * s, 40 * s, 984 * s, 984 * s], radius=200 * s, fill=NAVY)
    # A terminal window: title bar with three dots, then the prompt.
    d.rounded_rectangle([140 * s, 200 * s, 884 * s, 824 * s], radius=60 * s, fill=PANEL,
                        outline=ACCENT, width=int(22 * s))
    d.line([(150 * s, 300 * s), (874 * s, 300 * s)], fill=ACCENT, width=int(14 * s))
    for i, x in enumerate((215, 275, 335)):
        d.ellipse([(x - 20) * s, 230 * s, (x + 20) * s, 270 * s],
                  fill=ACCENT if i == 0 else (90, 60, 130))
    w = int(56 * s)
    d.line([(270 * s, 430 * s), (430 * s, 560 * s), (270 * s, 690 * s)], fill=WHITE,
           width=w, joint="curve")
    d.rounded_rectangle([490 * s, 650 * s, 740 * s, 706 * s], radius=14 * s, fill=ACCENT)
    return img


def main() -> None:
    OUT.mkdir(exist_ok=True)
    img = draw()
    img.resize((512, 512), Image.LANCZOS).save(OUT / "ares.png")
    img.resize((256, 256), Image.LANCZOS).save(OUT / "ares-256.png")
    img.save(OUT / "ares.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    img.save(OUT / "ares.icns")
    print("wrote", ", ".join(sorted(p.name for p in OUT.iterdir())))


if __name__ == "__main__":
    main()
