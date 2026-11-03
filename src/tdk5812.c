/*
 * libfprint TOD driver: Realtek 0bda:5812 USB bridge + TDK/InvenSense ultrasonic sensor
 * (Lenovo Yoga 9 14ITL5). Protocol reverse-engineered from RtsWBDI.dll 10.0.19041.27.
 *
 * Bridge transport (bulk 0x01 OUT / 0x82 IN):
 *   OUT header F0 <op> 00 00 <reg> 00 <lenLo> <lenHi>, data phase, IN 5-byte status (byte0==0)
 * Frames: SID(8) 0(4) ctr(4,BE) IV(16) AES-256-CBC(16752) AES-256-CMAC(16);
 *         plaintext holds a 135x62 8-bit image at 0x20b4.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "tdk5812"

#include "drivers_api.h"
#include "tdkmatch.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <string.h>
#include <errno.h>
#include <glib/gstdio.h>

#define EP_OUT 0x01
#define EP_IN  0x82
#define USB_TIMEOUT 2000

#define OP_READ_REG   0xE1
#define OP_WRITE_REG  0x61
#define OP_IMG_DATA   0x62
#define OP_IMG_STATUS 0x63
#define OP_SET_MODE   0xE4
#define OP_GET_KEY    0xE8   /* read stored TCFS record (read-only) */

#define MAX_CHUNK     0x3FF
#define FW_SIZE       0x7CA8
#define BLOB_SIZE     0x378
#define TCFS_SIZE     0x3B4
#define FRAME_READ    0x4200
#define FRAME_ENC     0x41A0
#define IMG_W         135
#define IMG_H         62
#define IMG_OFF       0x20B4
#define IMG_PX        (IMG_W * IMG_H)
#define ENROLL_STAGES 15
#define MATCH_THRESHOLD 12     /* RANSAC inliers; impostor max seen 4, genuine median ~47 */
#define MIN_KEYPOINTS 40
#define TEMPLATE_VERSION 1
#define POLL_MS       128
#define FINGER_OFF_MS 700
#define COVER_GOOD    0.75   /* accept immediately */
#define COVER_MIN     0.55   /* below this after settling: ask to re-place finger (matches collect.py) */
#define SETTLE_US     (1200 * 1000)

#ifndef TDK5812_FW_PATH
#define TDK5812_FW_PATH "/usr/local/share/tdk5812/tdk_dmp.bin"
#endif
#define FW_PATH       TDK5812_FW_PATH
#define STATE_DIR     "/var/lib/fprint/tdk5812"
#define PAIRING_PATH  STATE_DIR "/pairing.bin"

struct _FpiDeviceTdk5812
{
  FpDevice      parent;
  guint8        mac_key[32];
  guint8        enc_key[32];
  guint8        sid[8];
  guint32       counter;
  guint         poll_id;
  guint         poll_count;
  guint8        best[IMG_PX];  /* best frame seen while the finger settles */
  gboolean      have_best;
  gdouble       best_cover;
  gint64        settle_until;  /* monotonic us; 0 = not settling */
  GPtrArray    *enroll_imgs;   /* guint8[IMG_PX] each */
};

G_DECLARE_FINAL_TYPE (FpiDeviceTdk5812, fpi_device_tdk5812, FPI, DEVICE_TDK5812, FpDevice);
G_DEFINE_TYPE (FpiDeviceTdk5812, fpi_device_tdk5812, FP_TYPE_DEVICE);

/* ------------------------------------------------------------------ crypto */

static const guint8 kd_mask[32] = {
  0xd9, 0x15, 0x05, 0x14, 0x74, 0xc3, 0xff, 0xa1, 0xce, 0x63, 0x2a, 0xf4, 0x88, 0x29, 0xa7, 0x3c,
  0x36, 0x71, 0xce, 0xf5, 0xda, 0x6c, 0xaf, 0x1e, 0x54, 0x37, 0xfe, 0xde, 0x40, 0x03, 0xa2, 0xd3,
};
static const guint32 kd_masked[8] = {
  0x79fba23e, 0x37cf16bc, 0xfcc7fe95, 0x67afb329, 0x1acd47fb, 0xafcdb23c, 0xf1e5ad72, 0xa5d97e04,
};

static gboolean
aes_cmac (const guint8 key[32], const guint8 *data, gsize len, guint8 out[16])
{
  EVP_MAC *mac = EVP_MAC_fetch (NULL, "CMAC", NULL);
  EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new (mac) : NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_CIPHER, (char *) "AES-256-CBC", 0),
    OSSL_PARAM_construct_end (),
  };
  gsize outl = 0;
  gboolean ok = ctx &&
                EVP_MAC_init (ctx, key, 32, params) &&
                EVP_MAC_update (ctx, data, len) &&
                EVP_MAC_final (ctx, out, &outl, 16) && outl == 16;

  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok;
}

static gboolean
aes_cbc_decrypt (const guint8 key[32], const guint8 iv[16], const guint8 *in, gsize len, guint8 *out)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int l1 = 0, l2 = 0;
  gboolean ok = ctx &&
                EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv) &&
                EVP_CIPHER_CTX_set_padding (ctx, 0) &&
                EVP_DecryptUpdate (ctx, out, &l1, in, len) &&
                EVP_DecryptFinal_ex (ctx, out + l1, &l2) && (gsize) (l1 + l2) == len;

  EVP_CIPHER_CTX_free (ctx);
  return ok;
}

/* FUN_1800c1c00: counter KDF over CMAC, block = 00|i|label|00|ctx(8)|01 00 */
static gboolean
kdf (guint8 label, const guint8 ctx8[8], const guint8 key[32], guint8 out[32])
{
  for (int i = 0; i < 2; i++)
    {
      guint8 blk[16] = { 0, (guint8) i, label, 0 };
      memcpy (blk + 4, ctx8, 8);
      blk[14] = 1;
      if (!aes_cmac (key, blk, 16, out + 16 * i))
        return FALSE;
    }
  return TRUE;
}

static gboolean
descramble (const guint8 rnd[8], const guint8 scrambled[32], guint8 dev_key[32])
{
  guint8 master[32], k[32], iv[16] = { 0 };
  gboolean ok;

  for (int i = 0; i < 8; i++)
    for (int b = 0; b < 4; b++)
      master[i * 4 + b] = ((kd_masked[i] >> (8 * b)) & 0xff) ^ kd_mask[i * 4 + b];
  ok = kdf (0, rnd, master, k) && aes_cbc_decrypt (k, iv, scrambled, 32, dev_key);
  memset (master, 0, sizeof master);
  memset (k, 0, sizeof k);
  return ok;
}

/* ------------------------------------------------------------------ bridge */

/* fpi_usb_transfer_submit_sync() dereferences *error, so never hand it NULL */
static gboolean
xfer_sync (FpiUsbTransfer *t, guint timeout, GError **error)
{
  GError *local = NULL;
  gboolean ok = fpi_usb_transfer_submit_sync (t, timeout, &local);

  if (local)
    g_propagate_error (error, local);
  return ok;
}

static gboolean
bridge_cmd (FpDevice *dev, guint8 op, guint8 reg, gboolean in,
            guint8 *buf, gsize len, GError **error)
{
  g_autoptr(FpiUsbTransfer) t = NULL;
  guint8 hdr[8] = { 0xF0, op, 0, 0, reg, 0, len & 0xff, (len >> 8) & 0xff };

  t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (t, EP_OUT, 8);
  memcpy (t->buffer, hdr, 8);
  if (!xfer_sync (t, USB_TIMEOUT, error))
    return FALSE;
  g_clear_pointer (&t, fpi_usb_transfer_unref);

  if (len)
    {
      t = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (t, in ? EP_IN : EP_OUT, len);
      if (!in)
        memcpy (t->buffer, buf, len);
      if (!xfer_sync (t, USB_TIMEOUT, error))
        return FALSE;
      if (in)
        {
          if ((gsize) t->actual_length != len)
            {
              g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "short read %zd/%zu (op %02x)", t->actual_length, len, op);
              return FALSE;
            }
          memcpy (buf, t->buffer, len);
        }
      g_clear_pointer (&t, fpi_usb_transfer_unref);
    }

  t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (t, EP_IN, 64);
  if (!xfer_sync (t, USB_TIMEOUT, error))
    return FALSE;
  if (t->actual_length != 5 || t->buffer[0] != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "bad status (op %02x reg %02x): len %zd b0 %02x",
                   op, reg, t->actual_length, t->actual_length ? t->buffer[0] : 0);
      return FALSE;
    }
  return TRUE;
}

static gboolean
reg_read (FpDevice *dev, guint8 reg, guint8 *buf, gsize n, GError **error)
{
  return bridge_cmd (dev, OP_READ_REG, reg | 0x80, TRUE, buf, n, error);
}

static gboolean
reg_write (FpDevice *dev, guint8 reg, const guint8 *buf, gsize n, GError **error)
{
  return bridge_cmd (dev, OP_WRITE_REG, reg & 0x7f, FALSE, (guint8 *) buf, n, error);
}

static gboolean
reg_w8 (FpDevice *dev, guint8 reg, guint8 v, GError **error)
{
  return reg_write (dev, reg, &v, 1, error);
}

static gint
reg_r8 (FpDevice *dev, guint8 reg, GError **error)
{
  guint8 v;

  return reg_read (dev, reg, &v, 1, error) ? v : -1;
}

static gboolean
mem_read (FpDevice *dev, guint32 addr, guint8 *buf, gsize n, GError **error)
{
  guint8 a[4] = { addr, addr >> 8, addr >> 16, addr >> 24 };

  if (!reg_write (dev, 0x08, a, 4, error))
    return FALSE;
  for (gsize off = 0; off < n; off += MAX_CHUNK)
    if (!reg_read (dev, 0x0C, buf + off, MIN (MAX_CHUNK, n - off), error))
      return FALSE;
  return TRUE;
}

static gboolean
mem_write (FpDevice *dev, guint32 addr, const guint8 *buf, gsize n, GError **error)
{
  guint8 a[4] = { addr, addr >> 8, addr >> 16, addr >> 24 };

  if (!reg_write (dev, 0x08, a, 4, error))
    return FALSE;
  for (gsize off = 0; off < n; off += MAX_CHUNK)
    if (!reg_write (dev, 0x0C, buf + off, MIN (MAX_CHUNK, n - off), error))
      return FALSE;
  return TRUE;
}

/* ------------------------------------------------------------------ sensor */

static gboolean
timeout_err (GError **error, const char *what)
{
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "timeout: %s", what);
  return FALSE;
}

/* poll until (reg & mask) == want; returns FALSE on error/timeout */
static gboolean
poll_reg (FpDevice *dev, guint8 reg, guint8 mask, guint8 want, int ms, GError **error)
{
  for (int i = 0; i < ms; i++)
    {
      gint v = reg_r8 (dev, reg, error);
      if (v < 0)
        return FALSE;
      if ((v & mask) == want)
        return TRUE;
      g_usleep (1000);
    }
  return timeout_err (error, "poll_reg");
}

static gboolean
lp_mode_off (FpDevice *dev, GError **error)
{
  if (!reg_w8 (dev, 0x01, 0, error))
    return FALSE;
  g_usleep (5000);
  return poll_reg (dev, 0x39, 0x02, 0x02, 10, error);
}

static gboolean
wake (FpDevice *dev, GError **error)
{
  for (int i = 0; i < 200; i++)
    {
      gint v = reg_r8 (dev, 0x39, error);
      if (v < 0)
        return FALSE;
      if (v & 4)
        return TRUE;
      if (!reg_w8 (dev, 0x04, 0x20, error))
        return FALSE;
      g_usleep (1000);
    }
  return timeout_err (error, "wake");
}

static gint
cnf (FpDevice *dev, GError **error)
{
  gint v = -1;

  for (int i = 0; i < 100; i++)
    {
      v = reg_r8 (dev, 0x0E, error);
      if (v < 0)
        return -1;
      if ((v & 5) != 1)
        break;
      g_usleep (1000);
    }
  if (v & 1)
    {
      timeout_err (error, "CNF busy");
      return -1;
    }
  return v;
}

static gboolean
wait_irq (FpDevice *dev, GError **error)
{
  return poll_reg (dev, 0x03, 0xff, 0x01, 500, error);
}

static gboolean
dmp_mode (FpDevice *dev, guint mode, GError **error)
{
  gboolean special = mode <= 0x14 && ((0x101020u >> mode) & 1);

  if (special)
    {
      gint v;
      if (!reg_w8 (dev, 0x1D, mode, error) || !wait_irq (dev, error))
        return FALSE;
      if ((v = reg_r8 (dev, 0x55, error)) < 0)
        return FALSE;
      if (v == 1 && (!wake (dev, error) || !reg_w8 (dev, 0x55, 0, error) || !wait_irq (dev, error)))
        return FALSE;
      return cnf (dev, error) >= 0;
    }
  return wake (dev, error) && cnf (dev, error) >= 0 &&
         reg_w8 (dev, 0x1D, mode, error) && wait_irq (dev, error);
}

static gboolean
load_firmware (FpDevice *dev, GError **error)
{
  static const guint8 boot[][2] = {
    { 0x1B, 0x60 }, { 0x10, 0 }, { 0x11, 0 }, { 0x12, 1 }, { 0x14, 4 }, { 0x15, 0 },
    { 0x16, 1 }, { 0x18, 8 }, { 0x19, 0 }, { 0x1A, 1 }, { 0x7C, 1 },
  };
  g_autofree guint8 *fw = NULL;
  g_autofree guint8 *back = NULL;
  gsize fw_len = 0;
  guint8 ver[12];

  if (!g_file_get_contents (FW_PATH, (gchar **) &fw, &fw_len, error))
    return FALSE;
  if (fw_len != FW_SIZE)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL, "bad firmware size %zu", fw_len);
      return FALSE;
    }
  if (reg_r8 (dev, 0x00, error) != 0xAD)
    {
      if (error && !*error)
        g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED, "bad WHOAMI");
      return FALSE;
    }
  if (!lp_mode_off (dev, error) ||
      !reg_w8 (dev, 0x3A, 2, error))
    return FALSE;
  g_usleep (2000);
  if (!reg_w8 (dev, 0x04, 0x3F, error))
    return FALSE;
  g_usleep (1000);
  if (!lp_mode_off (dev, error) ||
      !reg_w8 (dev, 0x04, 1, error) ||
      !mem_write (dev, 0x10000, fw, fw_len, error))
    return FALSE;
  back = g_malloc (fw_len);
  if (!mem_read (dev, 0x10000, back, fw_len, error))
    return FALSE;
  if (memcmp (fw, back, fw_len) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "firmware readback mismatch");
      return FALSE;
    }
  for (guint i = 0; i < G_N_ELEMENTS (boot); i++)
    if (!reg_w8 (dev, boot[i][0], boot[i][1], error))
      return FALSE;
  if (!reg_w8 (dev, 0x3E, 4, error) ||
      !mem_read (dev, 0x16964, ver, sizeof ver, error))
    return FALSE;
  if (ver[0] != 4 || ver[1] != 7 || ver[2] != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "unexpected DMP version %d.%d.%d", ver[0], ver[1], ver[2]);
      return FALSE;
    }
  fp_dbg ("DMP firmware 4.7.0 loaded");
  return TRUE;
}

static gboolean
configure (FpDevice *dev, GError **error)
{
  const guint8 zero = 0;
  const guint8 gen[4] = { 0x5A, 0, 0, 0 };

  return mem_write (dev, 0x16AAF, &zero, 1, error) &&
         dmp_mode (dev, 1, error) &&
         dmp_mode (dev, 0x0E, error) &&
         mem_write (dev, 0x16E18, gen, 4, error) &&
         dmp_mode (dev, 5, error);
}

static gboolean
sec_start (FpDevice *dev, const guint8 *blob, GError **error)
{
  gint c = cnf (dev, error);

  if (c < 0)
    return FALSE;
  if (!(c & 0x20))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "start not allowed (CNF %02x)", c);
      return FALSE;
    }
  return mem_write (dev, 0x0, blob, BLOB_SIZE, error) &&
         reg_w8 (dev, 0x0D, 4, error) && cnf (dev, error) >= 0;
}

static gboolean
sec_enroll (FpDevice *dev, guint8 key[32], guint8 blob[BLOB_SIZE], GError **error)
{
  guint8 rnd[8], scr[32];
  gint c = cnf (dev, error);

  if (c < 0)
    return FALSE;
  if (!(c & 0x10))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "enroll not allowed (CNF %02x)", c);
      return FALSE;
    }
  if (RAND_bytes (rnd, sizeof rnd) != 1)
    return timeout_err (error, "RAND_bytes");
  return mem_write (dev, 0x3D8, rnd, 8, error) &&
         reg_w8 (dev, 0x0D, 2, error) && cnf (dev, error) >= 0 &&
         mem_read (dev, 0x0, blob, BLOB_SIZE, error) &&
         mem_read (dev, 0x3E0, scr, 32, error) &&
         descramble (rnd, scr, key);
}

static gboolean
sec_open (FpiDeviceTdk5812 *self, const guint8 dev_key[32], GError **error)
{
  FpDevice *dev = FP_DEVICE (self);
  guint8 resp[16], msg[16] = { 0 }, expect[16];
  gint c = cnf (dev, error);

  if (c < 0)
    return FALSE;
  if (!(c & 0x08) || (c & 0x40))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "open not allowed (CNF %02x)", c);
      return FALSE;
    }
  if (RAND_bytes (self->sid, 8) != 1)
    return timeout_err (error, "RAND_bytes");
  if (!mem_write (dev, 0x3D0, self->sid, 8, error) ||
      !reg_w8 (dev, 0x0D, 8, error) || cnf (dev, error) < 0 ||
      !poll_reg (dev, 0x39, 0x04, 0x00, 100, error) ||
      !reg_read (dev, 0x07, resp, 16, error))
    return FALSE;

  memcpy (msg, self->sid, 8);
  if (!kdf (2, self->sid, dev_key, self->mac_key) ||
      !aes_cmac (self->mac_key, msg, 16, expect))
    return timeout_err (error, "crypto");
  if (CRYPTO_memcmp (expect, resp, 16) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "session MAC mismatch");
      return FALSE;
    }
  if (!kdf (1, self->sid, dev_key, self->enc_key))
    return timeout_err (error, "crypto");
  self->counter = 0;
  return TRUE;
}

static void
save_pairing (const guint8 key[32], const guint8 blob[BLOB_SIZE])
{
  g_autoptr(GError) err = NULL;
  guint8 buf[32 + BLOB_SIZE];

  memcpy (buf, key, 32);
  memcpy (buf + 32, blob, BLOB_SIZE);
  if (g_mkdir_with_parents (STATE_DIR, 0700) != 0 ||
      !g_file_set_contents_full (PAIRING_PATH, (gchar *) buf, sizeof buf,
                                 G_FILE_SET_CONTENTS_CONSISTENT, 0600, &err))
    fp_warn ("could not save pairing: %s", err ? err->message : g_strerror (errno));
  memset (buf, 0, sizeof buf);
}

/* Restore a known pairing (ours, then Windows' record in the bridge); enroll only as fallback. */
static gboolean
pair_and_open (FpiDeviceTdk5812 *self, GError **error)
{
  FpDevice *dev = FP_DEVICE (self);
  g_autofree guint8 *local = NULL;
  gsize local_len = 0;
  guint8 tcfs[TCFS_SIZE], key[32], blob[BLOB_SIZE];
  gint c;

  if (g_file_get_contents (PAIRING_PATH, (gchar **) &local, &local_len, NULL) &&
      local_len == 32 + BLOB_SIZE)
    {
      g_autoptr(GError) e = NULL;
      if (sec_start (dev, local + 32, &e) && sec_open (self, local, &e))
        {
          fp_dbg ("session open with local pairing");
          return TRUE;
        }
      fp_dbg ("local pairing failed: %s", e->message);
      if (!load_firmware (dev, error) || !configure (dev, error))
        return FALSE;
    }

  if (bridge_cmd (dev, OP_GET_KEY, 0, TRUE, tcfs, TCFS_SIZE, NULL) && memcmp (tcfs, "TCFS", 4) == 0)
    {
      g_autoptr(GError) e = NULL;
      if (sec_start (dev, tcfs + 0x3C, &e) && sec_open (self, tcfs + 0x1C, &e))
        {
          fp_dbg ("session open with bridge (Windows) pairing record");
          save_pairing (tcfs + 0x1C, tcfs + 0x3C);
          memset (tcfs, 0, sizeof tcfs);
          return TRUE;
        }
      fp_dbg ("bridge pairing failed: %s", e->message);
      memset (tcfs, 0, sizeof tcfs);
      if (!load_firmware (dev, error) || !configure (dev, error))
        return FALSE;
    }

  if ((c = cnf (dev, error)) < 0)
    return FALSE;
  if (!(c & 0x10))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "no usable pairing and enroll not allowed (CNF %02x); power the laptop off fully", c);
      return FALSE;
    }
  if (!sec_enroll (dev, key, blob, error))
    return FALSE;
  save_pairing (key, blob);
  fp_info ("enrolled new sensor pairing");
  if (!sec_open (self, key, error))
    return FALSE;
  memset (key, 0, sizeof key);
  return TRUE;
}

/* ------------------------------------------------------------------ capture engine */

/* decrypt + authenticate a frame; copy the native (unprocessed) 135x62 image into out */
static gboolean
frame_decrypt (FpiDeviceTdk5812 *self, const guint8 *frame, guint8 *out, GError **error)
{
  g_autofree guint8 *plain = g_malloc (FRAME_ENC - 0x30);
  guint8 mac[16];
  guint32 ctr;

  if (memcmp (frame, self->sid, 8) != 0 || frame[8] | frame[9] | frame[10] | frame[11])
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "not an image frame");
      return FALSE;
    }
  ctr = (frame[12] << 24) | (frame[13] << 16) | (frame[14] << 8) | frame[15];
  if (ctr <= self->counter ||
      !aes_cmac (self->mac_key, frame, FRAME_ENC - 16, mac) ||
      CRYPTO_memcmp (mac, frame + FRAME_ENC - 16, 16) != 0 ||
      !aes_cbc_decrypt (self->enc_key, frame + 16, frame + 32, FRAME_ENC - 0x30, plain))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "frame authentication failed");
      return FALSE;
    }
  self->counter = ctr;
  memcpy (out, plain + IMG_OFF, IMG_PX);
  return TRUE;
}

/* fraction of 9x9 blocks with ridge contrast (stddev > 30 after a 1%/99% stretch) */
static gdouble
coverage (const guint8 *px)
{
  guint hist[256] = { 0 };
  guint lo = 0, hi = 255, acc;
  gint tot = 0, fg = 0;
  const gint B = 9;

  for (int i = 0; i < IMG_PX; i++)
    hist[px[i]]++;
  for (acc = 0; lo < 255 && (acc += hist[lo]) < IMG_PX / 100; lo++)
    ;
  for (acc = 0; hi > 0 && (acc += hist[hi]) < IMG_PX / 100; hi--)
    ;
  if (hi <= lo)
    return 0;
  for (gint by = 0; by + B <= IMG_H; by += B)
    for (gint bx = 0; bx + B <= IMG_W; bx += B)
      {
        gdouble sum = 0, sq = 0;
        for (gint y = 0; y < B; y++)
          for (gint x = 0; x < B; x++)
            {
              gdouble v = CLAMP (((gdouble) px[(by + y) * IMG_W + bx + x] - lo) * 255.0 / (hi - lo), 0, 255);
              sum += v;
              sq += v * v;
            }
        sum /= B * B;
        tot++;
        fg += (sq / (B * B) - sum * sum) > 30.0 * 30.0;
      }
  return tot ? (gdouble) fg / tot : 0;
}

static void
save_debug_image (const guint8 *px, gdouble cover, const char *tag)
{
  g_autofree gchar *path = NULL, *hdr = NULL;
  g_autoptr(GByteArray) b = NULL;

  if (!g_getenv ("TDK5812_SAVE_IMAGES"))
    return;
  path = g_strdup_printf (STATE_DIR "/img-%" G_GINT64_FORMAT "-%s-c%02d.pgm",
                          g_get_real_time () / 1000, tag, (gint) (cover * 100));
  hdr = g_strdup_printf ("P5\n%d %d\n255\n", IMG_W, IMG_H);
  b = g_byte_array_new ();
  g_byte_array_append (b, (guint8 *) hdr, strlen (hdr));
  g_byte_array_append (b, px, IMG_PX);
  g_file_set_contents (path, (gchar *) b->data, b->len, NULL);
}

static gboolean
arm (FpDevice *dev, GError **error)
{
  guint8 one = 1;

  return bridge_cmd (dev, OP_SET_MODE, 0, FALSE, &one, 1, error);
}

static void
stop_poll (FpiDeviceTdk5812 *self)
{
  g_clear_handle_id (&self->poll_id, g_source_remove);
  self->have_best = FALSE;
  self->best_cover = 0;
  self->settle_until = 0;
}

static void capture_done (FpiDeviceTdk5812 *self, const guint8 *img, GError *error);

static gboolean
capture_finish_best (FpiDeviceTdk5812 *self)
{
  self->poll_id = 0;
  self->settle_until = 0;
  if (self->best_cover < COVER_MIN)
    {
      fp_dbg ("best coverage %.2f too low", self->best_cover);
      self->have_best = FALSE;
      capture_done (self, NULL, fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
      return G_SOURCE_REMOVE;
    }
  fp_dbg ("using frame with coverage %.2f", self->best_cover);
  self->have_best = FALSE;
  capture_done (self, self->best, NULL);
  return G_SOURCE_REMOVE;
}

static gboolean
poll_cb (gpointer user_data)
{
  FpiDeviceTdk5812 *self = user_data;
  FpDevice *dev = FP_DEVICE (self);
  GError *error = NULL;
  g_autofree guint8 *frame = NULL;
  guint8 st = 0, img[IMG_PX];
  gdouble cover;

  if (++self->poll_count % 16 == 0 && !arm (dev, &error))
    goto fail;
  if (!bridge_cmd (dev, OP_IMG_STATUS, 0, TRUE, &st, 1, &error))
    goto fail;
  if (st != 1)
    {
      if (self->settle_until && g_get_monotonic_time () > self->settle_until)
        return capture_finish_best (self);
      return G_SOURCE_CONTINUE;
    }

  frame = g_malloc (FRAME_READ);
  if (!bridge_cmd (dev, OP_IMG_DATA, 0, TRUE, frame, FRAME_READ, &error) || !arm (dev, &error))
    goto fail;
  {
    g_autoptr(GError) ferr = NULL;
    if (!frame_decrypt (self, frame, img, &ferr))
      {
        fp_dbg ("ignoring frame: %s", ferr->message);
        return G_SOURCE_CONTINUE;
      }
  }
  if (!self->settle_until)
    fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT, FP_FINGER_STATUS_NEEDED);

  cover = coverage (img);
  fp_dbg ("frame after %u polls, coverage %.2f", self->poll_count, cover);
  if (!self->have_best || cover > self->best_cover)
    {
      memcpy (self->best, img, IMG_PX);
      self->best_cover = cover;
      self->have_best = TRUE;
    }
  if (self->best_cover >= COVER_GOOD)
    return capture_finish_best (self);
  if (!self->settle_until)
    self->settle_until = g_get_monotonic_time () + SETTLE_US;
  else if (g_get_monotonic_time () > self->settle_until)
    return capture_finish_best (self);
  return G_SOURCE_CONTINUE;

fail:
  self->poll_id = 0;
  capture_done (self, NULL, error);
  return G_SOURCE_REMOVE;
}

static void
capture_start (FpiDeviceTdk5812 *self)
{
  GError *error = NULL;

  stop_poll (self);
  if (!arm (FP_DEVICE (self), &error))
    {
      capture_done (self, NULL, error);
      return;
    }
  fpi_device_report_finger_status_changes (FP_DEVICE (self), FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_PRESENT);
  self->poll_count = 0;
  self->poll_id = g_timeout_add (POLL_MS, poll_cb, self);
}

/* after a touch: give the user time to lift, then throw away frames taken meanwhile */
static gboolean
lift_done_cb (gpointer user_data)
{
  FpiDeviceTdk5812 *self = user_data;
  FpDevice *dev = FP_DEVICE (self);
  guint8 st = 0;

  self->poll_id = 0;
  for (int i = 0; i < 8; i++)
    {
      g_autofree guint8 *junk = NULL;
      if (!bridge_cmd (dev, OP_IMG_STATUS, 0, TRUE, &st, 1, NULL) || st != 1)
        break;
      junk = g_malloc (FRAME_READ);
      bridge_cmd (dev, OP_IMG_DATA, 0, TRUE, junk, FRAME_READ, NULL);
      self->counter = MAX (self->counter, (guint32) ((junk[12] << 24) | (junk[13] << 16) | (junk[14] << 8) | junk[15]));
    }
  fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_PRESENT);
  capture_start (self);
  return G_SOURCE_REMOVE;
}

static void
wait_lift_then_capture (FpiDeviceTdk5812 *self)
{
  stop_poll (self);
  self->poll_id = g_timeout_add (FINGER_OFF_MS, lift_done_cb, self);
}

/* ------------------------------------------------------------------ templates & matching */

static GVariant *
templates_to_variant (GPtrArray *imgs)
{
  GVariantBuilder b;

  g_variant_builder_init (&b, G_VARIANT_TYPE ("aay"));
  for (guint i = 0; i < imgs->len; i++)
    g_variant_builder_add_value (&b, g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                                g_ptr_array_index (imgs, i),
                                                                IMG_PX, 1));
  return g_variant_new ("(qqqaay)", TEMPLATE_VERSION, IMG_W, IMG_H, &b);
}

/* best inlier score of probe against every enrolled image of a print; -1 if unusable */
static gint
score_print (FpPrint *print, const tdk_feat *probe)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) arr = NULL;
  guint16 ver, w, h;
  gint best = -1;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(qqqaay)")))
    return -1;
  g_variant_get (data, "(qqq@aay)", &ver, &w, &h, &arr);
  if (ver != TEMPLATE_VERSION || w != IMG_W || h != IMG_H)
    return -1;
  for (gsize i = 0; i < g_variant_n_children (arr); i++)
    {
      g_autoptr(GVariant) e = g_variant_get_child_value (arr, i);
      gsize n = 0;
      const guint8 *px = g_variant_get_fixed_array (e, &n, 1);
      tdk_feat *t;
      gint s;

      if (n != IMG_PX)
        continue;
      t = tdk_feat_new (px, IMG_W, IMG_H);
      s = tdk_feat_score (probe, t);
      tdk_feat_free (t);
      best = MAX (best, s);
    }
  return best;
}

/* ------------------------------------------------------------------ actions */

static void
enroll_capture_done (FpiDeviceTdk5812 *self, const guint8 *img, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  FpPrint *print = NULL;
  tdk_feat *f;
  gint nkp;

  if (error && error->domain == FP_DEVICE_RETRY)
    {
      fpi_device_enroll_progress (dev, self->enroll_imgs->len, NULL, error);
      wait_lift_then_capture (self);
      return;
    }
  if (error)
    {
      g_clear_pointer (&self->enroll_imgs, g_ptr_array_unref);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  f = tdk_feat_new (img, IMG_W, IMG_H);
  nkp = tdk_feat_count (f);
  tdk_feat_free (f);
  save_debug_image (img, coverage (img), "enroll");
  if (nkp < MIN_KEYPOINTS)
    {
      fp_dbg ("only %d keypoints, retry", nkp);
      fpi_device_enroll_progress (dev, self->enroll_imgs->len, NULL,
                                  fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
      wait_lift_then_capture (self);
      return;
    }

  g_ptr_array_add (self->enroll_imgs, g_memdup2 (img, IMG_PX));
  fp_dbg ("enroll sample %u (%d keypoints)", self->enroll_imgs->len, nkp);
  fpi_device_enroll_progress (dev, self->enroll_imgs->len, NULL, NULL);
  if ((gint) self->enroll_imgs->len < fp_device_get_nr_enroll_stages (dev))
    {
      wait_lift_then_capture (self);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", templates_to_variant (self->enroll_imgs), NULL);
  g_clear_pointer (&self->enroll_imgs, g_ptr_array_unref);
  fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_PRESENT);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
verify_capture_done (FpiDeviceTdk5812 *self, const guint8 *img, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  tdk_feat *probe;

  fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_PRESENT);
  if (error && error->domain == FP_DEVICE_RETRY)
    {
      if (action == FPI_DEVICE_ACTION_VERIFY)
        {
          fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, error);
          fpi_device_verify_complete (dev, NULL);
        }
      else
        {
          fpi_device_identify_report (dev, NULL, NULL, error);
          fpi_device_identify_complete (dev, NULL);
        }
      return;
    }
  if (error)
    {
      if (action == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_complete (dev, error);
      else
        fpi_device_identify_complete (dev, error);
      return;
    }

  save_debug_image (img, coverage (img), "probe");
  probe = tdk_feat_new (img, IMG_W, IMG_H);
  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *tmpl = NULL;
      gint s;

      fpi_device_get_verify_data (dev, &tmpl);
      s = score_print (tmpl, probe);
      fp_info ("verify score %d (threshold %d)", s, MATCH_THRESHOLD);
      fpi_device_verify_report (dev, s >= MATCH_THRESHOLD ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                NULL, NULL);
      tdk_feat_free (probe);
      fpi_device_verify_complete (dev, NULL);
    }
  else
    {
      GPtrArray *prints = NULL;
      FpPrint *match = NULL;
      gint best = -1;

      fpi_device_get_identify_data (dev, &prints);
      for (guint i = 0; i < prints->len; i++)
        {
          gint s = score_print (g_ptr_array_index (prints, i), probe);
          fp_dbg ("identify: print %u score %d", i, s);
          if (s >= MATCH_THRESHOLD && s > best)
            {
              best = s;
              match = g_ptr_array_index (prints, i);
            }
        }
      fp_info ("identify best score %d (threshold %d)", best, MATCH_THRESHOLD);
      tdk_feat_free (probe);
      fpi_device_identify_report (dev, match, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
    }
}

static void
capture_done (FpiDeviceTdk5812 *self, const guint8 *img, GError *error)
{
  switch (fpi_device_get_current_action (FP_DEVICE (self)))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      enroll_capture_done (self, img, error);
      break;

    case FPI_DEVICE_ACTION_VERIFY:
    case FPI_DEVICE_ACTION_IDENTIFY:
      verify_capture_done (self, img, error);
      break;

    default:
      g_clear_error (&error);
      break;
    }
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceTdk5812 *self = FPI_DEVICE_TDK5812 (dev);

  g_clear_pointer (&self->enroll_imgs, g_ptr_array_unref);
  self->enroll_imgs = g_ptr_array_new_with_free_func (g_free);
  capture_start (self);
}

static void
dev_verify_identify (FpDevice *dev)
{
  capture_start (FPI_DEVICE_TDK5812 (dev));
}

static void
dev_cancel (FpDevice *dev)
{
  FpiDeviceTdk5812 *self = FPI_DEVICE_TDK5812 (dev);
  GError *err = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");

  stop_poll (self);
  fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_NEEDED | FP_FINGER_STATUS_PRESENT);
  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      g_clear_pointer (&self->enroll_imgs, g_ptr_array_unref);
      fpi_device_enroll_complete (dev, NULL, err);
      break;

    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_verify_complete (dev, err);
      break;

    case FPI_DEVICE_ACTION_IDENTIFY:
      fpi_device_identify_complete (dev, err);
      break;

    default:
      g_error_free (err);
      break;
    }
}

/* ------------------------------------------------------------------ lifecycle */

static void
dev_open (FpDevice *dev)
{
  FpiDeviceTdk5812 *self = FPI_DEVICE_TDK5812 (dev);
  GError *error = NULL;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev), 0, 0, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }
  /* drain anything a previous (interrupted) user left queued on the bridge */
  for (int i = 0; i < 64; i++)
    {
      g_autoptr(FpiUsbTransfer) t = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (t, EP_IN, FRAME_READ);
      if (!xfer_sync (t, 50, NULL))
        break;
    }
  if (load_firmware (dev, &error) && configure (dev, &error))
    pair_and_open (self, &error);
  fpi_device_open_complete (dev, error);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceTdk5812 *self = FPI_DEVICE_TDK5812 (dev);
  GError *error = NULL;

  stop_poll (self);
  g_clear_pointer (&self->enroll_imgs, g_ptr_array_unref);
  memset (self->mac_key, 0, 32);
  memset (self->enc_key, 0, 32);
  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  fpi_device_close_complete (dev, error);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x0bda, .pid = 0x5812, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_tdk5812_init (FpiDeviceTdk5812 *self)
{
}

static void
fpi_device_tdk5812_finalize (GObject *obj)
{
  FpiDeviceTdk5812 *self = FPI_DEVICE_TDK5812 (obj);

  g_clear_pointer (&self->enroll_imgs, g_ptr_array_unref);
  G_OBJECT_CLASS (fpi_device_tdk5812_parent_class)->finalize (obj);
}

static void
fpi_device_tdk5812_class_init (FpiDeviceTdk5812Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = fpi_device_tdk5812_finalize;

  dev_class->id = "tdk5812";
  dev_class->full_name = "Realtek 5812 / TDK ultrasonic fingerprint sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;   /* no thermal throttling needed */

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify_identify;
  dev_class->identify = dev_verify_identify;
  dev_class->cancel = dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}

/* TOD entry point */
GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_tdk5812_get_type ();
}
