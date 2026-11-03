#!/bin/bash
# Build and install the tdk5812 libfprint TOD driver plus the sensor firmware.
# Tested on Ubuntu 24.04. Run from the repository root:  ./install.sh
set -euo pipefail
cd "$(dirname "$0")"

FW_PATH=/usr/local/share/tdk5812/tdk_dmp.bin

if ! lsusb -d 0bda:5812 >/dev/null 2>&1; then
  echo "warning: no 0bda:5812 device found; continuing anyway" >&2
fi

echo "==> installing build dependencies (sudo)"
sudo apt-get install -y --no-install-recommends \
  build-essential g++ meson ninja-build pkg-config cabextract \
  fprintd libpam-fprintd libfprint-2-tod-dev libssl-dev \
  libopencv-core-dev libopencv-imgproc-dev libopencv-features2d-dev libopencv-calib3d-dev

echo "==> building"
meson setup build -Dfirmware_path="$FW_PATH" --wipe >/dev/null 2>&1 || meson setup build -Dfirmware_path="$FW_PATH"
ninja -C build

echo "==> fetching firmware from the Microsoft Update Catalog"
python3 firmware/fetch-firmware.py build/tdk_dmp.bin

echo "==> installing (sudo)"
sudo install -D -m 644 build/tdk_dmp.bin "$FW_PATH"
sudo ninja -C build install
sudo systemctl restart fprintd 2>/dev/null || true

echo
echo "Done. Enroll a finger with GNOME Settings > System > Users > Fingerprint Login,"
echo "or:  fprintd-enroll -f right-index-finger \"$USER\""
echo "Optional, fingerprint for sudo:  sudo pam-auth-update --enable fprintd"
