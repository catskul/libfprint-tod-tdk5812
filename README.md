# libfprint-tod-tdk5812

A Linux fingerprint driver for the **Realtek `0bda:5812` "USB2.0 Finger Print Bridge" with a TDK/InvenSense
ultrasonic ("UltraPrint") sensor**, as found in the **Lenovo Yoga 9 14ITL5 (82BG)**.

It is a [libfprint](https://fprint.freedesktop.org/) "TOD" plugin, so it works with the stock Ubuntu `fprintd`:
GNOME login and lock screen, `fprintd-enroll`/`fprintd-verify`, and optionally `sudo` through `pam_fprintd`.

> **Status: experimental, works on the author's machine.** The matcher is home-grown, not a certified
> commercial one. Treat fingerprint auth as a convenience and keep a password.

## Supported hardware

| USB ID | `bcdDevice` | Sensor | Supported |
|---|---|---|---|
| `0bda:5812` | `05.02` | TDK ultrasonic (WHOAMI `0xAD`), DMP firmware 4.7.0 | ✅ |
| `0bda:5812` | `00.02` / `07.01` | Qualcomm 3D Sonic (Windows driver `LenovoQti*`) | ❌ (different sensor) |

Check yours with `lsusb -v -d 0bda:5812 | grep bcdDevice`. On unsupported revisions the driver fails cleanly with
"bad WHOAMI".

## Install (Ubuntu 24.04)

```bash
git clone https://github.com/catskul/libfprint-tod-tdk5812.git && cd libfprint-tod-tdk5812
./install.sh
```

`install.sh` installs the build dependencies, builds the plugin, **downloads the official Windows driver package
from the Microsoft Update Catalog** and extracts the sensor firmware from it (checking SHA-256 at every step;
the firmware is not redistributed here), then installs:

- `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-tod-tdk5812.so`
- `/usr/local/share/tdk5812/tdk_dmp.bin`

Then enroll in **Settings → System → Users → Fingerprint Login**, or run
`fprintd-enroll -f right-index-finger $USER` (15 touches; vary the position slightly and lift between touches).
If you also want fingerprint for `sudo`, run `sudo pam-auth-update --enable fprintd`.

Remove everything with `./uninstall.sh`. This also deletes the fingerprints you enrolled with `fprintd`.

## How it works

1. **Bring-up.** At every open the driver resets the sensor, uploads the DMP firmware to its RAM, and configures it,
   mirroring the Windows driver's sequence.
2. **Pairing.** The sensor only sends authenticated, encrypted frames. The driver first restores a saved pairing
   (`/var/lib/fprint/tdk5812/pairing.bin`, root-only). Failing that, it uses the pairing record Windows left in the
   bridge (read-only, so the reader keeps working in Windows if you dual-boot). As a last resort it enrolls a new
   pairing. It never writes to the bridge's flash.
3. **Capture.** It arms the sensor, polls for a frame, and verifies and decrypts it (AES-256-CMAC + AES-256-CBC).
   It waits up to ~1.2 s for a well-covered frame, and asks you to re-place your finger if coverage stays low.
4. **Matching.** The 135×62 px (≈9.5×4.4 mm) image holds only ~10 minutiae, too few for libfprint's NBIS/bozorth3.
   So the driver matches like other small-sensor matchers: SIFT keypoints (ridge features and sweat pores, which
   this sensor resolves) on a CLAHE-enhanced 2× image, ratio-test matching, and a RANSAC similarity transform.
   **Score = geometrically consistent inliers; match ≥ 12.** A print stores the 15 enrolled images
   (≈125 KB), and features are computed at verify time.

### Measured accuracy (one person, small dataset)

20 touches of the enrolled finger and 18 touches of 4 other fingers; 500 random 15-touch enrollments:

| Threshold | False reject (per touch) | False accept |
|---|---|---|
| ≥ 12 inliers | ~6 % | 0 / 9 000 attempts (impostor max score 4) |

That is a small, single-person dataset. Contributions of more data are very welcome; see `tools/`.

## Repository layout

- `src/`: the driver (C) and matcher (C++/OpenCV)
- `firmware/fetch-firmware.py`: verified download and extraction of the firmware
- `tools/`: Python userspace driver for research, data collection and matcher evaluation (see `tools/README.md`)
- `docs/PROTOCOL.md`: the reverse-engineered USB/sensor/crypto protocol

## Legal

This driver was written for interoperability, by analysing the publicly distributed Windows driver
(`RtsWBDI.dll` 10.0.19041.27). No vendor code, firmware or decompiled source is included. The firmware is fetched
from Microsoft by the user. The source does contain the protocol's obfuscated key-derivation constant, which
interoperability requires.

Licensed under the LGPL-2.1-or-later (see `LICENSE`), like libfprint.
