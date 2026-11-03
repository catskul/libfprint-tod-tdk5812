"""Mirror UPrintDeviceCtrl::setupDevice: firmware -> DMP modes -> enroll -> session open.
RAM-only on the sensor; never writes the bridge's stored key record (op 0x68)."""
import os
import sys
import time

from tdkfp import TdkFp
import tdkcrypto

HERE = os.path.dirname(os.path.abspath(__file__))
FW = open(os.environ.get("TDK5812_FW", "/usr/local/share/tdk5812/tdk_dmp.bin"), "rb").read()
MODE_MASK = 0x101020  # modes 5, 12, 20 take the "special" path


class Sensor:
    def __init__(self):
        self.fp = TdkFp()
        self.w = self.fp.write_reg

    def r(self, reg):
        return self.fp.read_reg(reg)[0]

    def poll(self, cond, ms, what):
        for _ in range(ms):
            if cond():
                return
            time.sleep(0.001)
        raise TimeoutError(what)

    # ---- inv_fp helpers ----
    def lp_mode_off(self):
        self.w(0x01, 0)
        time.sleep(0.005)
        self.poll(lambda: self.r(0x39) & 2, 10, "lp_mode (0x39 bit1)")

    def wake(self):  # FUN_1800ba0c8
        for _ in range(200):
            if self.r(0x39) & 4:
                return
            self.w(0x04, 0x20)
            time.sleep(0.001)
        raise TimeoutError("wake (0x39 bit2)")

    def cnf(self):  # FUN_1800ba89c
        for _ in range(100):
            v = self.r(0x0E)
            if (v & 5) != 1:
                break
            time.sleep(0.001)
        if v & 1:
            raise TimeoutError(f"CNF busy 0x{v:02x}")
        return v

    def wait_irq(self, ms=500):  # FUN_1800ba908
        self.poll(lambda: self.r(0x03) == 1, ms, "DMP irq (reg 0x03)")

    def dmp_mode(self, mode):  # FUN_1800b9df0
        special = mode <= 0x14 and (MODE_MASK >> mode) & 1
        if special:
            self.w(0x1D, mode)
            self.wait_irq()
            if self.r(0x55) == 1:
                self.wake()
                self.w(0x55, 0)
                self.wait_irq()
            self.cnf()
        else:
            self.wake()
            self.cnf()
            self.w(0x1D, mode)
            self.wait_irq()

    # ---- setupDevice ----
    def load_firmware(self):
        assert self.r(0x00) == 0xAD, "bad WHOAMI"
        self.lp_mode_off()
        self.w(0x3A, 2); time.sleep(0.002)
        self.w(0x04, 0x3F); time.sleep(0.001)
        self.lp_mode_off()
        self.w(0x04, 1)
        self.fp.mem_write(0x10000, FW)
        if self.fp.mem_read(0x10000, len(FW)) != FW:
            raise RuntimeError("firmware readback mismatch")
        for reg, val in [(0x1B, 0x60), (0x10, 0), (0x11, 0), (0x12, 1), (0x14, 4), (0x15, 0),
                         (0x16, 1), (0x18, 8), (0x19, 0), (0x1A, 1), (0x7C, 1)]:
            self.w(reg, val)
        self.w(0x3E, 4)
        ver = self.fp.mem_read(0x16964, 12)
        assert ver[:3] == bytes([4, 7, 0]), f"unexpected fw version {ver.hex()}"
        print("firmware 4.7.0 loaded")

    def configure(self):
        self.fp.mem_write(0x16AAF, bytes([0]))           # bypass_gain_comp(0)
        t0 = self.fp.mem_read(0x16AA0, 4); t1 = self.fp.mem_read(0x16AA4, 4)
        print("timer0 defaults", int.from_bytes(t0, "little"), int.from_bytes(t1, "little"))
        self.dmp_mode(1); print("dmp mode 1 ok")
        self.dmp_mode(0x0E); print("dmp mode 0xE ok")
        self.fp.mem_write(0x16E18, (0x5A).to_bytes(4, "little"))  # custom generator
        self.dmp_mode(5); print("dmp mode 5 ok, CNF=0x%02x" % self.cnf())

    def enroll(self):  # FUN_1800b9eb4 + iid_Descramble
        c = self.cnf()
        if not c & 0x10:
            raise RuntimeError(f"enroll not allowed, CNF=0x{c:02x}")
        rnd = os.urandom(8)
        self.fp.mem_write(0x3D8, rnd)
        self.w(0x0D, 2)
        self.cnf()
        blob = self.fp.mem_read(0x0, 0x378)
        scr = self.fp.mem_read(0x3E0, 0x20)
        return tdkcrypto.descramble(rnd, scr), blob

    def start(self, blob):  # inv_fp_start, FUN_1800ba820: restore saved key state
        c = self.cnf()
        if not c & 0x20:
            raise RuntimeError(f"start not allowed, CNF=0x{c:02x}")
        self.fp.mem_write(0x0, blob)
        self.w(0x0D, 4)
        return self.cnf()

    def open_session(self, dev_key):  # FUN_1800ba4fc + iid_VerifySessionOpen
        c = self.cnf()
        if not c & 0x08 or c & 0x40:
            raise RuntimeError(f"session open not allowed, CNF=0x{c:02x}")
        sid = os.urandom(8)
        self.fp.mem_write(0x3D0, sid)
        self.w(0x0D, 8)
        self.cnf()
        self.poll(lambda: not (self.r(0x39) & 4), 100, "session (0x39 bit2 clear)")
        resp = self.fp.read_reg(0x07, 16)
        return tdkcrypto.Session(dev_key, sid, resp)


# shared with the libfprint driver: key(32) + blob(0x378), root-only
PAIRING = os.environ.get("TDK5812_PAIRING", "/var/lib/fprint/tdk5812/pairing.bin")


def load_pairings(fp):
    """Yield (name, key, blob) candidates: local pairing first, then Windows' record in the bridge."""
    if os.path.exists(PAIRING):
        d = open(PAIRING, "rb").read()
        yield "local pairing.bin", d[:32], d[32:32 + 0x378]
    try:
        d = fp.cmd_in(0xE8, 0, 0x3B4)  # read-only: retrieve stored TCFS record
    except Exception:
        return
    if d[:4] == b"TCFS":
        yield "Windows TCFS record (bridge)", d[0x1C:0x3C], d[0x3C:0x3C + 0x378]


def save_pairing(key, blob):
    os.makedirs(os.path.dirname(PAIRING), mode=0o700, exist_ok=True)
    fd = os.open(PAIRING, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key + blob)


def bring_up():
    """Full init; returns (sensor, session). Enrolls if allowed, else restores a pairing."""
    s = Sensor()
    s.load_firmware()
    s.configure()
    c = s.cnf()
    if c & 0x10:
        key, blob = s.enroll()
        save_pairing(key, blob)
        print("enrolled fresh (saved to pairing.bin); CNF 0x%02x" % s.cnf())
        return s, s.open_session(key)
    for name, key, blob in load_pairings(s.fp):
        print(f"trying {name}: start -> CNF 0x{s.start(blob):02x}")
        try:
            sess = s.open_session(key)
        except (RuntimeError, ValueError) as e:
            print("  failed:", e)
            continue
        if name != "local pairing.bin":
            save_pairing(key, blob)
        print(f"  session open with {name}")
        return s, sess
    raise RuntimeError("no usable pairing; a full power-off should re-allow enroll")


if __name__ == "__main__":
    s, sess = bring_up()
    print("SESSION OPEN — MAC verified. CNF now 0x%02x" % s.cnf())
    s.fp.close()
