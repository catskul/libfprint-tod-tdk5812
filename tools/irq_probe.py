"""Does the bridge report finger touches on its interrupt endpoints (0x83 / 0x84)?

Brings the sensor up like the driver, arms it, then for N seconds listens on both interrupt
endpoints while also polling the bulk image-status flag, printing timestamped events so the two
can be correlated. Read-only apart from the usual bring-up and arm commands.

usage: sudo venv/bin/python -u tools/irq_probe.py [seconds]   (stop fprintd first)
"""
import sys
import time

import usb.core

from setup_session import bring_up

SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 60
FRAME_READ = 0x4200


def main():
    s, sess = bring_up()
    fp = s.fp
    arm = lambda: fp.cmd_out(0xE4, 0, bytes([1]))
    t0 = time.monotonic()
    ts = lambda: f"{time.monotonic() - t0:7.3f}s"

    # drain anything already sitting on the interrupt endpoints
    for ep in (0x83, 0x84):
        try:
            while True:
                d = fp.dev.read(ep, 16, timeout=20)
                print(f"{ts()}  (stale) EP {ep:#04x}: {bytes(d).hex(' ')}", flush=True)
        except usb.core.USBError:
            pass

    arm()
    print(f"{ts()}  armed - TOUCH THE READER NOW (a few times, lifting in between) for {SECONDS:.0f} s",
          flush=True)
    counts = {0x83: 0, 0x84: 0, "frames": 0}
    last_status, polls = None, 0
    while time.monotonic() - t0 < SECONDS:
        for ep in (0x83, 0x84):
            try:
                d = fp.dev.read(ep, 16, timeout=40)
                counts[ep] += 1
                print(f"{ts()}  >>> INTERRUPT EP {ep:#04x}: {bytes(d).hex(' ')}", flush=True)
            except usb.core.USBTimeoutError:
                pass
            except usb.core.USBError as e:
                print(f"{ts()}  EP {ep:#04x} error: {e}", flush=True)
        polls += 1
        if polls % 25 == 0:
            arm()  # re-arm about every 2 s, like the driver
        st = fp.image_status()
        if st != last_status:
            print(f"{ts()}  bulk image status -> {st}", flush=True)
            last_status = st
        if st == 1:
            raw = fp.image_data(FRAME_READ)
            counts["frames"] += 1
            try:
                sess.decrypt_frame(raw[:0x41A0])
                kind = "image frame"
            except ValueError as e:
                kind = f"non-image ({e})"
            print(f"{ts()}  bulk frame read: {kind}", flush=True)
            arm()
    print(f"\nDONE. interrupt events: EP 0x83 = {counts[0x83]}, EP 0x84 = {counts[0x84]}; "
          f"bulk frames = {counts['frames']}", flush=True)
    fp.close()


if __name__ == "__main__":
    main()
