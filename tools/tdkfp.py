"""Userspace driver pieces for Realtek 0bda:5812 bridge + TDK ultrasonic FP sensor.

Reverse-engineered from RtsWBDI.dll (Windows driver 10.0.19041.27).

Bridge transport (bulk EP 0x01 OUT / 0x82 IN):
  OUT  header  F0 <op> 00 00 <reg> 00 <len_lo> <len_hi>
  data phase   <len> bytes (direction depends on op)
  IN   status  5 bytes, byte0 == 0 -> OK
Ops: E1 readReg(IN) 61 writeReg(OUT) 62 getImageData(IN) 63 getImageStatus(IN,1)
     E4 setSensorMode(OUT,1) 68 storeSecSessionKey(OUT) E8 retrieveSecSessionKey(IN)

Sensor (InvenSense-style SPI regs, reg|0x80 = read):
  0x00 WHOAMI (=0xAD)   0x03 ?ready   0x0E status   0x2B OTP access (2=on)
  0x08 memory address (4 bytes LE)    0x0C memory data window
"""
import usb.core
import usb.util

EP_OUT, EP_IN = 0x01, 0x82
OK = 0


class BridgeError(Exception):
    pass


class TdkFp:
    MAX_CHUNK = 0x400 - 1

    def __init__(self):
        self.dev = usb.core.find(idVendor=0x0BDA, idProduct=0x5812)
        if self.dev is None:
            raise BridgeError("device not found")
        if self.dev.is_kernel_driver_active(0):
            raise BridgeError("kernel driver bound")
        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        self._drain()

    def close(self):
        usb.util.release_interface(self.dev, 0)

    # ---- bridge transport ----
    def _drain(self):
        try:
            while True:
                self.dev.read(EP_IN, 64, timeout=50)
        except usb.core.USBError:
            pass

    def _hdr(self, op, reg, length):
        return bytes([0xF0, op, 0, 0, reg & 0xFF, 0, length & 0xFF, (length >> 8) & 0xFF])

    def _status(self):
        st = bytes(self.dev.read(EP_IN, 64, timeout=2000))
        if len(st) != 5 or st[0] != OK:
            raise BridgeError(f"bad status {st.hex(' ')}")
        return st

    def cmd_in(self, op, reg, length):
        self.dev.write(EP_OUT, self._hdr(op, reg, length), timeout=2000)
        data = b""
        while len(data) < length:
            # request exactly what's left so we never swallow the status packet
            data += bytes(self.dev.read(EP_IN, length - len(data), timeout=2000))
        self._status()
        return data[:length]

    def cmd_out(self, op, reg, payload):
        self.dev.write(EP_OUT, self._hdr(op, reg, len(payload)), timeout=2000)
        if payload:
            self.dev.write(EP_OUT, payload, timeout=2000)
        self._status()

    # ---- sensor registers ----
    def read_reg(self, reg, n=1):
        return self.cmd_in(0xE1, reg | 0x80, n)

    def write_reg(self, reg, payload):
        if isinstance(payload, int):
            payload = bytes([payload])
        self.cmd_out(0x61, reg & 0x7F, payload)

    # ---- sensor memory window ----
    def mem_read(self, addr, n):
        self.write_reg(0x08, addr.to_bytes(4, "little"))
        out = b""
        while len(out) < n:
            k = min(self.MAX_CHUNK, n - len(out))
            out += self.read_reg(0x0C, k)
        return out

    def mem_write(self, addr, data):
        self.write_reg(0x08, addr.to_bytes(4, "little"))
        for i in range(0, len(data), self.MAX_CHUNK):
            self.write_reg(0x0C, data[i:i + self.MAX_CHUNK])

    def otp_read(self, addr, n):
        self.write_reg(0x2B, 2)
        try:
            return self.mem_read(addr, n)
        finally:
            self.write_reg(0x2B, 0)

    # ---- bridge-level image path ----
    def image_status(self):
        return self.cmd_in(0x63, 0, 1)[0]

    def image_data(self, n):
        return self.cmd_in(0x62, 0, n)
