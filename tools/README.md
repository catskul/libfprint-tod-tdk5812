# Research tools

A Python userspace driver for the sensor, plus scripts to collect data and evaluate the matcher.
These scripts need raw USB access, so they **run as root** and **while fprintd is stopped** (`sudo systemctl stop fprintd`).
They share the firmware (`/usr/local/share/tdk5812/tdk_dmp.bin`, override with `TDK5812_FW`) and the pairing file
(`/var/lib/fprint/tdk5812/pairing.bin`, override with `TDK5812_PAIRING`) with the installed driver.

```bash
python3 -m venv venv && venv/bin/pip install pyusb cryptography numpy
sudo venv/bin/python tools/setup_session.py      # bring-up + pairing + session open
sudo venv/bin/python tools/capture.py 3 60       # capture 3 frames -> captures/
sudo venv/bin/python -u tools/collect.py         # guided collection -> data/<finger>_<nn>.pgm
```

| file | purpose |
|---|---|
| `tdkfp.py` | bridge transport, registers, memory window |
| `tdkcrypto.py` | KDF, descramble, session verify, frame decrypt |
| `setup_session.py` | bring-up mirroring the Windows driver; `bring_up()` |
| `capture.py`, `topng.py` | raw capture and PNG rendering |
| `collect.py` | guided dataset collection (20 genuine + 4×5 other fingers) |
| `feat_eval.py` | Python prototype of the matcher plus FAR/FRR simulation (needs `python3-opencv`) |
| `match-matrix.c` | score matrix using the driver's exact C++ matcher (build line at the top of the file) |

**Privacy:** `data/` and `captures/` hold fingerprint images. They are git-ignored; don't publish them.
