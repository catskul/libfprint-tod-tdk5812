# Realtek 0bda:5812 + TDK ultrasonic sensor: protocol notes

Derived from `RtsWBDI.dll` 10.0.19041.27 (Windows UMDF WBDI driver, `REV_0502`). Function names refer to that
binary's own debug strings. Addresses are VAs in the DLL.

## USB

One vendor interface: bulk `0x01` OUT, bulk `0x82` IN (64 B packets), and interrupt `0x83`/`0x84` (silent; see below).

Every bridge command:

```
OUT  F0 <op> 00 00 <reg> 00 <len_lo> <len_hi>      8-byte header
I/O  <len> bytes                                    data phase (direction by op)
IN   <status> xx xx xx xx                           5 bytes, status 0 = OK
```

| op | name (Windows) | data |
|---|---|---|
| `E1` | readReg | IN `len` bytes from sensor register `reg` (`reg` has bit 7 set = read) |
| `61` | writeReg | OUT `len` bytes to sensor register `reg` |
| `62` | getImageData | IN `len` (0x4200) bytes: the frame buffered by the bridge |
| `63` | getImageStatus | IN 1 byte: 1 = a frame is ready |
| `E4` | setSensorMode | OUT 1 byte: 1 = arm capture (re-armed every ~2 s while waiting) |
| `68` | storeSecSessionKey | OUT 0x3B4 bytes: persist pairing record in bridge flash (**the driver never uses this**) |
| `E8` | retrieveSecSessionKey | IN 0x3B4 bytes: read pairing record (`"TCFS"` magic) |

`UpdateMcuFwEx`/`FW.BIN` (bridge MCU flash update) exists in the Windows driver. Never touch it.

### No touch events: polling is the only way (tested 2026-11-07)

Touches are reported **only** through the polled `getImageStatus` flag. Windows polls it every 128 ms; this driver
polls every 64 ms.

- **Interrupt endpoints `0x83`/`0x84`:** Windows opens both pipes but never reads them. With the sensor armed, they
  delivered no data during 22 real touches (`tools/irq_probe.py`).
- **Opcodes `0x64`/`0x65`:** command templates exist in the DLL, but no code references them. They have not been
  sent (their meaning is unknown).
- **USB remote wakeup:** the configuration attribute `0xa0` advertises it, but no touch-triggered wakeup was seen.
  With runtime autosuspend allowed, the device resumed on a fixed ~1.2 s rhythm. That resume came from the host side
  (same rhythm with wakeup disabled), and the bridge captured **no** frames while suspending
  (`tools/wake_probe.py`). So keep the device awake while waiting for a finger.

## Sensor registers (InvenSense-style, SPI behind the bridge)

| reg | use |
|---|---|
| `0x00` | WHOAMI = `0xAD` |
| `0x01` | low-power mode (write 0; then `0x39` bit 1 set) |
| `0x03` | DMP interrupt/done flag (poll == 1) |
| `0x04` | reset/wake control (`0x3F` reset, `0x20` wake, `0x01` before FW load) |
| `0x07` | session-open response (16 bytes) |
| `0x08` | memory address (4 bytes LE) |
| `0x0C` | memory data window (auto-increment, ≤1023 B per transfer) |
| `0x0D` | security command: 2 = enroll, 4 = start (restore), 8 = open session |
| `0x0E` | CNF/status: bit0 busy, bit1 ready, 0x08 open allowed, 0x10 enroll allowed, 0x20 start allowed, 0x40 in session |
| `0x1D` | DMP mode |
| `0x2B` | OTP access (2 = on) |
| `0x39` | power/state (bit1 awake, bit2 busy) |
| `0x3A` | `2` = hardware reset |
| `0x55` | DMP mode-change handshake |

Memory: DMP RAM at `0x10000` (firmware), version block at `0x16964` (`04 07 00`), OTP UID at `0x8600`,
security mailbox at `0x0` (0x378-byte blob), `0x3D0`/`0x3D8` (nonces) and `0x3E0` (scrambled key).

## Bring-up (`UPrintDeviceCtrl::setupDevice`)

1. WHOAMI == 0xAD. Then low-power off: `0x01=0`, wait for `0x39 & 2`.
2. Hardware reset: `0x3A=2`, then `0x04=0x3F`, then low-power off again.
3. `0x04=1`. Write the 31 912-byte DMP image to `0x10000`, read it back and compare.
4. Boot registers: `1B=60 10=00 11=00 12=01 14=04 15=00 16=01 18=08 19=00 1A=01 7C=01`, then `3E=04`.
5. Check the version at `0x16964` (4.7.0). `mem[0x16AAF]=0` (bypass gain compensation).
6. DMP modes 1 → 0x0E, then `mem[0x16E18]=0x5A` ("custom generator"), then mode 5.

Mode change: modes 5/12/20 write `0x1D`, wait `0x03==1`, and if `0x55==1` wake and write `0x55=0`. Other modes wake,
wait CNF, write `0x1D`, and wait `0x03==1`.

## Security

All primitives are standard: **AES-256-CMAC**, a counter-mode **KDF over CMAC**, and **AES-256-CBC**.

```
KDF(label, ctx8, key) = CMAC(key, 00|00|label|00|ctx8|00 00 01 00) || CMAC(key, 00|01|label|00|ctx8|00 00 01 00)
MASTER = masked_constant XOR mask          (FUN_1800c0f30; see src/tdk5812.c)
```

- **Enroll** (CNF 0x10): host writes rnd8 → `0x3D8`, `0x0D=2`. It reads blob (0x378 @ `0x0`) and scr32 (@ `0x3E0`).
  `devkey = AES-CBC-dec(KDF(0, rnd8, MASTER), iv=0, scr32)`. Persist `(devkey, blob)`.
- **Start** (CNF 0x20, e.g. after a firmware reload): write the blob → `0x0`, `0x0D=4`.
  The sensor remembers that it is enrolled across firmware reloads, but apparently not across power loss.
- **Open** (CNF 0x08): host writes SID8 → `0x3D0`, `0x0D=8`, waits `0x39` bit 2 clear, then reads resp16 from reg `0x07`.
  `mac = KDF(2, SID, devkey)`; require `CMAC(mac, SID || 0^8) == resp`. `enc = KDF(1, SID, devkey)`.
- **Bridge record** (`E8`, 0x3B4 B): `"TCFS" | SID(8) | resp(16) | devkey(32) @0x1C | blob(0x378) @0x3C`.

## Frames

`getImageData` returns 0x4200 bytes. The first 0x41A0 are:

```
SID(8) | 00000000 | counter(4, BE, strictly increasing) | IV(16) | AES-256-CBC(enc) ciphertext (16752) | CMAC(mac)(16)
```

The CMAC covers everything before it. The plaintext holds a **135×62 8-bit image at offset 0x20B4**. The first half
of the plaintext is a second (uncompensated?) image and is unused. Some packets after arming are not image frames
(their SID differs); ignore them.
