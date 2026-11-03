"""Capture and decrypt fingerprint frames (CBioDev::_CaptureThread equivalent).

usage: capture.py [n_frames] [timeout_s]
Writes ../captures/<ts>_<i>.{enc,plain,pgm}
"""
import os
import sys
import time

from setup_session import bring_up

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "captures")
W, H, IMG_OFF = 135, 62, 0x20B4
FRAME_READ, FRAME_ENC = 0x4200, 0x41A0

n_frames = int(sys.argv[1]) if len(sys.argv) > 1 else 1
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 60
os.makedirs(OUT, exist_ok=True)

s, sess = bring_up()
print("session open; place a finger on the sensor", flush=True)

fp = s.fp
arm = lambda: fp.cmd_out(0xE4, 0, bytes([1]))  # setSensorMode(1)
arm()
got, polls, t_end = 0, 0, time.time() + timeout
while got < n_frames and time.time() < t_end:
    time.sleep(0.128)
    polls += 1
    if polls % 16 == 0:
        arm()
    if fp.image_status() != 1:
        continue
    raw = fp.image_data(FRAME_READ)
    ts = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.join(OUT, f"{ts}_{got}")
    open(base + ".enc", "wb").write(raw)
    try:
        plain = sess.decrypt_frame(raw[:FRAME_ENC])
    except ValueError as e:
        print("frame received but decrypt failed:", e, flush=True)
        arm()
        continue
    open(base + ".plain", "wb").write(plain)
    img = plain[IMG_OFF:IMG_OFF + W * H]
    with open(base + ".pgm", "wb") as f:
        f.write(f"P5\n{W} {H}\n255\n".encode() + img)
    print(f"frame {got}: decrypted {len(plain)} B, counter {sess.counter}, "
          f"img min/max/mean {min(img)}/{max(img)}/{sum(img)/len(img):.1f} -> {base}.pgm", flush=True)
    got += 1
    arm()
print(f"done: {got} frame(s)")
s.fp.close()
