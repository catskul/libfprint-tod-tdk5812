"""Render .plain captures to PNG: 135x62 image at 0x20b4, contrast-stretched, 4x."""
import struct, sys, zlib
W, H, OFF, S = 135, 62, 0x20B4, 4
def png(path, rows):
    raw = b"".join(b"\0" + bytes(r) for r in rows)
    ch = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", len(rows[0]), len(rows), 8, 0, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))
for p in sys.argv[1:]:
    img = open(p, "rb").read()[OFF:OFF + W * H]
    lo, hi = sorted(img)[len(img) // 100], sorted(img)[-len(img) // 100]
    st = [max(0, min(255, (v - lo) * 255 // max(1, hi - lo))) for v in img]
    rows = [[st[y * W + x] for x in range(W) for _ in range(S)] for y in range(H) for _ in range(S)]
    png(p[:-6] + ".png", rows); print(p[:-6] + ".png", lo, hi)
