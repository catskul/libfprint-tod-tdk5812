"""Host-side crypto of the TDK sensor ("iidconfidentio.c" in RtsWBDI.dll).

All primitives are standard: AES-256-CMAC, SP800-108-style counter KDF over CMAC,
and AES-256-CBC. Constants come from FUN_1800c0f30 (iid_Descramble).
"""
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# FUN_1800c0f30: local_88[0..31] (mask) and local_68..local_4c (masked master key)
_MASK = bytes([0xd9, 0x15, 0x05, 0x14, 0x74, 0xc3, 0xff, 0xa1, 0xce, 0x63, 0x2a, 0xf4, 0x88, 0x29, 0xa7, 0x3c,
               0x36, 0x71, 0xce, 0xf5, 0xda, 0x6c, 0xaf, 0x1e, 0x54, 0x37, 0xfe, 0xde, 0x40, 0x03, 0xa2, 0xd3])
_MASKED = b"".join(v.to_bytes(4, "little") for v in (
    0x79fba23e, 0x37cf16bc, 0xfcc7fe95, 0x67afb329, 0x1acd47fb, 0xafcdb23c, 0xf1e5ad72, 0xa5d97e04))
MASTER = bytes(a ^ b for a, b in zip(_MASKED, _MASK))

LABEL_DESCRAMBLE, LABEL_ENC, LABEL_MAC = 0, 1, 2


def cmac(key, data):
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def kdf(label, ctx8, key):
    """FUN_1800c1c00: two CMAC blocks over 00|i|label|00|ctx(8)|01 00."""
    assert len(ctx8) == 8 and len(key) == 32
    out = b""
    for i in range(2):
        out += cmac(key, bytes([0, i, label, 0]) + ctx8 + bytes([0, 0, 1, 0]))
    return out


def cbc_decrypt(key, iv, data):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def descramble(rand8, scrambled32):
    """iid_Descramble: device key from enroll output."""
    return cbc_decrypt(kdf(LABEL_DESCRAMBLE, rand8, MASTER), bytes(16), scrambled32)


class Session:
    """iid_VerifySessionOpen + iid_VerifyAndDecrypt."""

    def __init__(self, dev_key, sid8, response16):
        self.mac_key = kdf(LABEL_MAC, sid8, dev_key)
        expect = cmac(self.mac_key, sid8 + bytes(8))
        if expect != response16:
            raise ValueError(f"session MAC mismatch: want {response16.hex()} got {expect.hex()}")
        self.enc_key = kdf(LABEL_ENC, sid8, dev_key)
        self.sid = sid8
        self.counter = 0

    def decrypt_frame(self, frame):
        n = len(frame)
        if n % 16 or n <= 0x30:
            raise ValueError("bad frame length")
        if frame[0:8] != self.sid or frame[8:12] != bytes(4):
            raise ValueError("frame SID/header mismatch")
        ctr = int.from_bytes(frame[12:16], "big")
        if ctr <= self.counter:
            raise ValueError(f"replayed counter {ctr}")
        if cmac(self.mac_key, frame[:n - 16]) != frame[n - 16:]:
            raise ValueError("frame MAC mismatch")
        self.counter = ctr
        return cbc_decrypt(self.enc_key, frame[16:32], frame[32:n - 16])
