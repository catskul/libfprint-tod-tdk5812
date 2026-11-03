#!/bin/bash
# Remove the tdk5812 driver, its firmware and its pairing state.
# Enrolled prints made with this driver are removed too (they are useless without it).
set -euo pipefail

TOD_DIR=$(pkg-config --variable=tod_driversdir libfprint-2-tod-1 2>/dev/null || echo /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1)

echo "==> deleting fingerprints enrolled for $USER"
fprintd-delete "$USER" 2>/dev/null || true
echo "==> removing driver, firmware and pairing state (sudo)"
sudo rm -f "$TOD_DIR/libfprint-tod-tdk5812.so"
sudo rm -rf /usr/local/share/tdk5812 /var/lib/fprint/tdk5812
sudo systemctl restart fprintd 2>/dev/null || true
echo "Done. Build dependencies installed by install.sh were left in place."
