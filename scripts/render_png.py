#!/usr/bin/env python3
"""Render a captured terminal transcript as a PNG.

The images in docs/screenshots are produced from the *real* output of the
commands (docs/evidence/*.txt); only the presentation — dark terminal styling,
font, framing — is generated here. That keeps the screenshots honest: what is
visible is what the tools printed.

Usage:
    python scripts/render_png.py docs/evidence/api-demo.txt docs/screenshots/api-demo.png \
        --title "node scripts/demo.mjs" --footer "Windows 11 · Node 24 · 2026-10-20"
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

BG = (13, 17, 23)
BAR = (22, 27, 34)
BORDER = (48, 54, 61)
TEXT = (201, 209, 217)
DIM = (139, 148, 158)
GREEN = (126, 211, 137)
RED = (248, 113, 113)
CYAN = (103, 200, 227)
YELLOW = (230, 192, 106)
WHITE = (240, 246, 252)


def read_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig")
    return data.decode("utf-8", errors="replace")


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        r"C:\Windows\Fonts\DejaVuSansMono-Bold_0.ttf" if bold else r"C:\Windows\Fonts\DejaVuSansMono_0.ttf",
        r"C:\Windows\Fonts\consolasb.ttf" if bold else r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\cour.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default()


def line_color(line: str) -> tuple[int, int, int]:
    stripped = line.strip()
    if stripped.startswith("PASS") or "] PASS" in stripped:
        return GREEN
    if stripped.startswith("FAIL") or "] FAIL" in stripped:
        return RED
    if stripped.startswith("RESULT") or stripped.startswith("RCE CONFIRMED"):
        return YELLOW
    if stripped.startswith("===") or stripped.startswith("--- "):
        return CYAN
    if stripped.startswith("$") or stripped.startswith(">"):
        return WHITE
    return TEXT


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument("--title", default="")
    parser.add_argument("--footer", default="")
    parser.add_argument("--columns", type=int, default=132)
    parser.add_argument("--font-size", type=int, default=15)
    args = parser.parse_args()

    raw = ANSI_RE.sub("", read_text(Path(args.source))).replace("ℹ", "i")
    lines: list[str] = []
    for line in raw.replace("\t", "    ").splitlines():
        line = line.rstrip()
        if len(line) <= args.columns:
            lines.append(line)
        else:
            # soft-wrap long diagnostics without breaking words where possible
            while len(line) > args.columns:
                cut = line.rfind(" ", 0, args.columns)
                cut = cut if cut > args.columns // 2 else args.columns
                lines.append(line[:cut])
                line = "    " + line[cut:].lstrip()
            lines.append(line)

    font = load_font(args.font_size)
    title_font = load_font(args.font_size + 1, bold=True)
    small = load_font(args.font_size - 3)

    char_width = font.getlength("M")
    width = int(char_width * args.columns) + 56
    bar_height = 44
    line_height = args.font_size + 8
    footer_height = 34 if args.footer else 12
    height = bar_height + 20 + line_height * max(1, len(lines)) + footer_height

    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, width, bar_height], fill=BAR)
    draw.line([(0, bar_height), (width, bar_height)], fill=BORDER)

    for index, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        cx = 20 + index * 22
        draw.ellipse([cx, 15, cx + 13, 28], fill=color)

    if args.title:
        draw.text((96, 13), args.title, font=title_font, fill=WHITE)

    y = bar_height + 14
    for line in lines:
        draw.text((24, y), line, font=font, fill=line_color(line))
        y += line_height

    if args.footer:
        draw.text((24, height - footer_height + 8), args.footer, font=small, fill=DIM)

    draw.rectangle([0, 0, width - 1, height - 1], outline=BORDER)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    image.save(args.output)
    print(f"{args.output}  {width}x{height}  ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
