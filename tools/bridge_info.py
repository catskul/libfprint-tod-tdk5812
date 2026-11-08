"""Read the Realtek bridge's firmware info and (optionally) dump its code flash.

READ-ONLY. This reproduces only the *read* half of the Windows driver's
`CBioDev::EnterDownloadMode` path: a vendor IN control request (bmRequestType 0xC0,
bRequest 0x2E) that returns a 32-byte device-info block and the bridge's code region.

It never writes. Do NOT add the write/update requests (`CUsbDev::UpdateFlashEx`,
`UpdateMcuFwEx`) or send bridge opcodes 0x64 / 0x65: the bridge can rewrite its own
flash, which holds the firmware and the secure-session key material, so an unknown
write can permanently brick the reader (Windows Hello included).

usage: sudo venv/bin/python -u tools/bridge_info.py [--dump out.bin]   (stop fprintd first)
"""
import sys

import usb.core
import usb.util

REQ_TYPE_VENDOR_IN = 0xC0
REQ_READ = 0x2E          # EnterDownloadMode read (info block + code flash)
INFO_WINDEX = 0x1000     # wIndex that returns the 32-byte info block
INFO_LEN = 0x20
FLASH_LEN = 0xE000       # size the Windows UpdateFlashEx read-back compares
CHUNK = 0x1000


def ctrl_read(dev, windex, length):
    return bytes(dev.ctrl_transfer(REQ_TYPE_VENDOR_IN, REQ_READ, 0, windex, length, timeout=3000))


def main():
    dump_path = None
    if len(sys.argv) >= 3 and sys.argv[1] == "--dump":
        dump_path = sys.argv[2]

    dev = usb.core.find(idVendor=0x0BDA, idProduct=0x5812)
    if dev is None:
        sys.exit("reader 0bda:5812 not found")
    if dev.is_kernel_driver_active(0):
        sys.exit("a kernel driver holds the device; stop fprintd first")

    print("bcdDevice: %04x" % dev.bcdDevice)
    info = ctrl_read(dev, INFO_WINDEX, INFO_LEN)
    vid = (info[6] << 8) | info[7]
    pid = (info[8] << 8) | info[9]
    rev = (info[10] << 8) | info[11]
    strings = [s.decode("latin1") for s in info[12:].split(b"\0") if s]
    print("info block: %s" % info.hex(" "))
    print("  device: VID %04X PID %04X REV %04X" % (vid, pid, rev))
    print("  versions: %s" % ", ".join(strings))

    if dump_path:
        print("dumping %#x bytes of bridge code flash (read-only)..." % FLASH_LEN)
        data = b"".join(ctrl_read(dev, off, CHUNK) for off in range(0, FLASH_LEN, CHUNK))
        with open(dump_path, "wb") as f:
            f.write(data)
        print("wrote %d bytes to %s" % (len(data), dump_path))

    usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
