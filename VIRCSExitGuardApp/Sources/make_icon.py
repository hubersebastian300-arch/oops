#!/usr/bin/env python3
import os
import struct
import zlib


TRANSPARENT = (0, 0, 0, 0)
OUTLINE = (53, 31, 18, 255)
BROWN = (132, 80, 37, 255)
MANE = (31, 25, 21, 255)
TAN = (190, 122, 55, 255)
CREAM = (232, 184, 101, 255)
BLACK = (7, 7, 7, 255)


def rect(canvas, x0, y0, x1, y1, color):
    for y in range(y0, y1):
        for x in range(x0, x1):
            if 0 <= x < 32 and 0 <= y < 32:
                canvas[y][x] = color


def make_base():
    sprite = [
        "................................",
        "................................",
        "..............OO................",
        ".............OBBO...............",
        ".............OBBBO..............",
        "............OBBBBBBO............",
        "............OBBBBMMO............",
        "...........OBBBBBMMO............",
        "..........OMBBBBBMMO............",
        ".........OMMBBBBBBBBO...........",
        "........OMMMBBBBBBBBBO..........",
        "........OMMBBBBBBBBBBBOO........",
        ".......OMMBBBBBBBBBBBBBBOO......",
        ".......OMMBBBBKBBBBBBBBBBO......",
        "......OMMMBBBBBBBBBBBBTTTBBO....",
        "......OMMBBBBBBBBBBBBTTTTTBKO...",
        ".....OMMMBBBBBBBBBBBBTTTTTTOO...",
        ".....OMMBBBBBBBBBBBBBBTTTCCO....",
        "....OMMMBBBBBBBBBBBBBBOOCCO.....",
        "....OMMBBBBBBBBBBBBBO..OOO......",
        "...OMMMBBBBBBBBBBBBBO...........",
        "...OMMMBBBBBBBBBBBBO............",
        "..OMMMMMBBBBBBBBBBO.............",
        "..OMMMMMMBBBBBBBBO..............",
        ".OMMMMMMMMBBBBBBO...............",
        ".OMMMMMMMMMBBBBO................",
        ".OMMMMMMMMMMBO..................",
        "..OMMMMMMMMMO...................",
        "...OMMMMMMMO....................",
        "....OOOOOOO.....................",
        "................................",
        "................................",
    ]
    palette = {
        ".": TRANSPARENT,
        "O": OUTLINE,
        "B": BROWN,
        "M": MANE,
        "T": TAN,
        "C": CREAM,
        "K": BLACK,
    }
    assert len(sprite) == 32
    canvas = []
    for row in sprite:
        assert len(row) == 32
        canvas.append([palette[ch] for ch in row])
    return canvas


def scale(canvas, size):
    pixels = []
    for y in range(size):
        source_y = min(31, int(y * 32 / size))
        row = []
        for x in range(size):
            source_x = min(31, int(x * 32 / size))
            row.append(canvas[source_y][source_x])
        pixels.append(row)
    return pixels


def write_png(path, pixels):
    height = len(pixels)
    width = len(pixels[0])
    raw = bytearray()
    for row in pixels:
        raw.append(0)
        for r, g, b, a in row:
            raw.extend([r, g, b, a])
    png = bytearray()
    png.extend(b"\x89PNG\r\n\x1a\n")

    def chunk(kind, data):
        png.extend(struct.pack(">I", len(data)))
        png.extend(kind)
        png.extend(data)
        png.extend(struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    chunk(b"IDAT", zlib.compress(bytes(raw), level=9))
    chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def main():
    base = make_base()
    out_dir = "horse.iconset"
    os.makedirs(out_dir, exist_ok=True)
    names = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ]
    for name, size in names:
        write_png(os.path.join(out_dir, name), scale(base, size))
    write_png("horse-preview.png", scale(base, 256))


if __name__ == "__main__":
    main()
