"""Can a touch wake the reader from USB autosuspend (USB remote wakeup)?

1. bring the sensor up and arm it (same as the driver), then let go of it
2. temporarily allow runtime autosuspend (0.5 s) with remote wakeup enabled, via usbfs
   USBDEVFS_ALLOW_SUSPEND; original sysfs power settings are restored at the end
3. baseline phase (don't touch): the device should suspend and stay suspended
4. touch phase: a remote wakeup shows up as runtime_status suspended -> active
Afterwards, check whether the bridge buffered a frame from the touch.

usage: sudo venv/bin/python -u tools/wake_probe.py [baseline_s] [touch_s]   (stop fprintd first)
"""
import fcntl
import glob
import os
import sys
import time

import usb.util

from setup_session import bring_up

BASELINE = float(sys.argv[1]) if len(sys.argv) > 1 else 15
TOUCH = float(sys.argv[2]) if len(sys.argv) > 2 else 30
USBDEVFS_FORBID_SUSPEND = 0x5521  # _IO('U', 33)
USBDEVFS_ALLOW_SUSPEND = 0x5522   # _IO('U', 34)


def find_sysfs():
    for d in glob.glob("/sys/bus/usb/devices/*"):
        try:
            if open(d + "/idVendor").read().strip() == "0bda" and open(d + "/idProduct").read().strip() == "5812":
                return d
        except OSError:
            pass
    sys.exit("reader not found")


def rd(path):
    return open(path).read().strip()


def wr(path, val):
    with open(path, "w") as f:
        f.write(val)


def main():
    sysd = find_sysfs()
    pw = sysd + "/power/"
    saved = {k: rd(pw + k) for k in ("control", "autosuspend_delay_ms", "wakeup")}
    print("saved power settings:", saved, flush=True)

    s, sess = bring_up()
    s.fp.cmd_out(0xE4, 0, bytes([1]))          # arm
    s.fp.close()
    usb.util.dispose_resources(s.fp.dev)       # close our libusb handle
    print("sensor armed and released", flush=True)

    node = "/dev/bus/usb/%03d/%03d" % (int(rd(sysd + "/busnum")), int(rd(sysd + "/devnum")))
    fd = None
    try:
        wr(pw + "wakeup", os.environ.get("WAKE_PROBE_WAKEUP", "enabled"))  # "disabled" = control run
        wr(pw + "autosuspend_delay_ms", "500")
        wr(pw + "control", "auto")
        fd = os.open(node, os.O_RDWR)
        fcntl.ioctl(fd, USBDEVFS_ALLOW_SUSPEND)

        t0 = time.monotonic()
        last = None
        resumes = {"baseline": 0, "touch": 0}
        phase = "baseline"
        print(f"BASELINE {BASELINE:.0f}s: do NOT touch the reader", flush=True)
        while time.monotonic() - t0 < BASELINE + TOUCH:
            t = time.monotonic() - t0
            if phase == "baseline" and t >= BASELINE:
                phase = "touch"
                print(f"{t:6.2f}s  >>> TOUCH PHASE {TOUCH:.0f}s: touch the reader now, a few times <<<", flush=True)
            st = rd(pw + "runtime_status")
            if st != last:
                print(f"{t:6.2f}s  runtime_status = {st}", flush=True)
                if last == "suspended" and st in ("resuming", "active"):
                    resumes[phase] += 1
                last = st
            time.sleep(0.05)
        print(f"\nresumes from suspend: baseline={resumes['baseline']}  touch={resumes['touch']}", flush=True)
        print("wakeup_count:", rd(pw + "wakeup_count") if os.path.exists(pw + "wakeup_count") else "n/a", flush=True)
    finally:
        if fd is not None:
            try:
                fcntl.ioctl(fd, USBDEVFS_FORBID_SUSPEND)
            except OSError:
                pass
            os.close(fd)
        for k in ("control", "autosuspend_delay_ms", "wakeup"):
            wr(pw + k, saved[k])
        print("restored power settings:", {k: rd(pw + k) for k in saved}, flush=True)

    # did the bridge keep a frame from the touch?
    from tdkfp import TdkFp
    fp = TdkFp()
    print("bridge image status after test:", fp.image_status(), flush=True)
    fp.close()


if __name__ == "__main__":
    main()
