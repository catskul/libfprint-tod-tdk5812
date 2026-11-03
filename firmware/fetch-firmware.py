#!/usr/bin/env python3
"""Download the official Windows driver from the Microsoft Update Catalog and extract the
TDK sensor's DMP firmware from it. The firmware is not redistributed by this project.

usage: fetch-firmware.py [output_path]   (default: ./tdk_dmp.bin)
needs: cabextract
"""
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request

# "Realtek Semiconductor - Biometric - 10.0.19041.27" (Windows 21H2+), update id 9dc59ff3-52be-475d-870b-f392a2c1b733
CAB_URL = ("https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2021/09/"
           "1956e6b2-27f6-45af-aaf8-74892748c8dd_43d40c413169f3737ad3dfffa0219b5823b4b23f.cab")
CAB_SHA256 = "96d195c9000e71eab95a0c07386a37ae65da841a37655a546c65066e486e7290"
DLL_NAME = "RtsWBDI.dll"
DLL_SHA256 = "0cc9b0493389e3af407ee605220ae315bb2e0515d18da0d0e6f737185400b59c"
FW_VA, FW_LEN = 0x180148BE0, 0x7CA8
FW_SHA256 = "d55b50a8c853ac459815e8bcd8473f7741c3f6242a63e1a83fc7e4955e522956"


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def va_to_offset(pe, va):
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, e + 6)[0]
    optsz = struct.unpack_from("<H", pe, e + 20)[0]
    base = struct.unpack_from("<Q", pe, e + 24 + 24)[0]
    rva = va - base
    for i in range(nsec):
        _, vsz, vaddr, rawsz, rawptr = struct.unpack_from("<8sIIII", pe, e + 24 + optsz + 40 * i)
        if vaddr <= rva < vaddr + max(vsz, rawsz):
            return rawptr + rva - vaddr
    raise ValueError("address not in any section")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "tdk_dmp.bin"
    if not shutil.which("cabextract"):
        sys.exit("cabextract is required (sudo apt install cabextract)")
    with tempfile.TemporaryDirectory() as tmp:
        cab = os.path.join(tmp, "driver.cab")
        print("downloading Windows driver package from Microsoft Update Catalog...")
        with urllib.request.urlopen(CAB_URL, timeout=60) as r, open(cab, "wb") as f:
            shutil.copyfileobj(r, f)
        if sha256(open(cab, "rb").read()) != CAB_SHA256:
            sys.exit("ERROR: driver package hash mismatch")
        subprocess.run(["cabextract", "-q", "-d", tmp, "-F", DLL_NAME, cab], check=True,
                       stderr=subprocess.DEVNULL)
        dll = open(os.path.join(tmp, DLL_NAME), "rb").read()
        if sha256(dll) != DLL_SHA256:
            sys.exit("ERROR: driver DLL hash mismatch")
        off = va_to_offset(dll, FW_VA)
        fw = dll[off:off + FW_LEN]
        if sha256(fw) != FW_SHA256:
            sys.exit("ERROR: extracted firmware hash mismatch")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as f:
        f.write(fw)
    print(f"firmware ({len(fw)} bytes, sha256 {FW_SHA256[:16]}...) written to {out}")


if __name__ == "__main__":
    main()
