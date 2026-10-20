#!/usr/bin/env python3
"""Draw the Verano shield icon at 16/32/48/128 px. Standard library only (zlib + struct)."""
import math
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "icons")
NAVY = (30, 41, 64)
RIM = (169, 184, 214)
WHITE = (255, 255, 255)
SS = 4  # supersampling factor for anti-aliasing


def in_shield(x, y, inset=0.0):
    """Shield in a 0..1 box: flat top, straight sides, curved point at the bottom."""
    left, right, top = 0.14 + inset, 0.86 - inset, 0.08 + inset
    if y < top or x < left or x > right:
        return False
    mid = 0.5
    shoulder = 0.52
    if y <= shoulder:
        return True
    # Below the shoulder the sides curve in to the point at y = 0.94 - inset.
    bottom = 0.94 - inset
    t = (y - shoulder) / (bottom - shoulder)
    if t > 1:
        return False
    half = (right - left) / 2 * math.cos(t * math.pi / 2)
    return abs(x - mid) <= half


def on_segment(px, py, ax, ay, bx, by, width):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    cx, cy = ax + t * dx, ay + t * dy
    return (px - cx) ** 2 + (py - cy) ** 2 <= (width / 2) ** 2


def colour_at(x, y):
    if not in_shield(x, y):
        return None
    if not in_shield(x, y, inset=0.055):
        return RIM
    # Check mark.
    w = 0.11
    if on_segment(x, y, 0.32, 0.50, 0.45, 0.64, w) or on_segment(x, y, 0.45, 0.64, 0.70, 0.34, w):
        return WHITE
    return NAVY


def render(size):
    n = size * SS
    rows = []
    for py in range(size):
        row = bytearray([0])  # filter type 0
        for px in range(size):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    c = colour_at((px * SS + sx + 0.5) / n, (py * SS + sy + 0.5) / n)
                    if c:
                        r += c[0]; g += c[1]; b += c[2]; a += 255
            hits = a // 255
            if hits:
                row += bytes([r // hits, g // hits, b // hits, a // (SS * SS)])
            else:
                row += bytes([0, 0, 0, 0])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for s in (16, 32, 48, 128):
        with open(os.path.join(OUT, f"icon{s}.png"), "wb") as f:
            f.write(render(s))
        print(f"icons/icon{s}.png")
