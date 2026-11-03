"""Guided, non-interactive dataset collection.

usage: sudo venv/bin/python scripts/collect.py [plan]
Saves native (unstretched) 135x62 images to data/<finger>_<nn>.pgm
"""
import os
import sys
import time

import numpy as np

from setup_session import bring_up

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "data")
W, H, IMG_OFF = 135, 62, 0x20B4
FRAME_READ, FRAME_ENC = 0x4200, 0x41A0

PLAN = [("right-index", 20), ("left-index", 5), ("right-middle", 5), ("right-thumb", 5), ("left-thumb", 5)]


def say(msg):
    print(msg, flush=True)


def coverage(img):
    a = img.astype(np.float32)
    lo, hi = np.percentile(a, 1), np.percentile(a, 99)
    a = np.clip((a - lo) * 255 / max(hi - lo, 1), 0, 255)
    B = 9
    blocks = [a[y:y + B, x:x + B].std() > 30 for y in range(0, H - B + 1, B) for x in range(0, W - B + 1, B)]
    return float(np.mean(blocks))


os.makedirs(OUT, exist_ok=True)
s, sess = bring_up()
fp = s.fp
arm = lambda: fp.cmd_out(0xE4, 0, bytes([1]))


def grab(timeout=30.0, settle=1.2, good=0.75, minimum=0.55):
    """Wait for a touch; return the best-covered frame seen during the settle window."""
    arm()
    best, best_c, t_end, settle_end, polls = None, -1, time.time() + timeout, None, 0
    while time.time() < t_end:
        time.sleep(0.128)
        polls += 1
        if polls % 16 == 0:
            arm()
        if fp.image_status() != 1:
            if settle_end and time.time() > settle_end:
                break
            continue
        raw = fp.image_data(FRAME_READ)
        arm()
        try:
            plain = sess.decrypt_frame(raw[:FRAME_ENC])
        except ValueError:
            continue
        img = np.frombuffer(plain[IMG_OFF:IMG_OFF + W * H], np.uint8).reshape(H, W)
        c = coverage(img)
        if c > best_c:
            best, best_c = img.copy(), c
        if best_c >= good:
            break
        settle_end = settle_end or time.time() + settle
        if time.time() > settle_end:
            break
    if best is None or best_c < minimum:
        return None, best_c
    return best, best_c


try:
    for finger, n in PLAN:
        nice = finger.replace("-", " ").upper()
        say(f"\n=== Next: {nice} ({n} touches). Get ready... ===")
        for t in (3, 2, 1):
            say(f"   {t}")
            time.sleep(1)
        k = 0
        while k < n:
            say(f">>> {nice} touch {k + 1}/{n}: PRESS NOW (flat, vary position a little)")
            img, c = grab()
            if img is None:
                say(f"    poor coverage ({c:.2f}) or timeout - lift and try again")
                time.sleep(1.0)
                continue
            path = os.path.join(OUT, f"{finger}_{k:02d}.pgm")
            with open(path, "wb") as f:
                f.write(f"P5\n{W} {H}\n255\n".encode() + img.tobytes())
            say(f"    got it (coverage {c:.2f}) - LIFT")
            k += 1
            time.sleep(1.2)
            # drain anything captured while lifting
            while fp.image_status() == 1:
                fp.image_data(FRAME_READ)
    say("\nALL DONE - thank you!")
finally:
    s.fp.close()
