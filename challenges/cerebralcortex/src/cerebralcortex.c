#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void initialise_monitor_handles(void);

extern const uint8_t cerebralcortex_fs[];
extern const size_t cerebralcortex_fs_len;

static uint32_t crc32_ieee(const uint8_t *data, size_t n) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) {
    crc ^= data[i];
    for (int b = 0; b < 8; b++) {
      uint32_t m = -(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & m);
    }
  }
  return ~crc;
}

static void deobfuscate_flag(char *out, size_t outlen) {
  /* Obfuscated form of: ictf{this_was_brainy} */
  static const uint8_t obf[] = {
      0xf0, 0x8b, 0x8f, 0xac, 0x5e, 0x40, 0x6f, 0x7f, 0x12, 0x2f, 0x34,
      0x33, 0xde, 0xe3, 0xed, 0xec, 0x88, 0x91, 0xa5, 0xa3, 0x48,
  };
  const size_t n = sizeof(obf);
  if (outlen < n + 1) {
    /* Not expected; just fail closed. */
    if (outlen) out[0] = '\0';
    return;
  }

  for (size_t i = 0; i < n; i++) {
    uint8_t k = (uint8_t)(0xA5u ^ (uint8_t)((i * 17u + 0x3Cu) & 0xFFu));
    out[i] = (char)(obf[i] ^ k);
  }
  out[n] = '\0';
}

static int from_hex8(const uint8_t *p, uint32_t *out) {
  uint32_t v = 0;
  for (int i = 0; i < 8; i++) {
    uint8_t c = p[i];
    v <<= 4;
    if (c >= '0' && c <= '9') {
      v |= (uint32_t)(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      v |= (uint32_t)(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      v |= (uint32_t)(c - 'A' + 10);
    } else {
      return 0;
    }
  }
  *out = v;
  return 1;
}

static size_t align4(size_t x) { return (x + 3u) & ~3u; }

static int read_flag_from_embedded_fs(char *out, size_t outlen) {
  /*
   * Minimal parser for a "newc" cpio archive.
   * We look for an entry named "flag" (treated as "/flag").
   */
  const uint8_t *p = cerebralcortex_fs;
  const uint8_t *end = cerebralcortex_fs + cerebralcortex_fs_len;

  while (p + 110 <= end) {
    if (memcmp(p, "070701", 6) != 0) return 0;

    uint32_t filesize = 0, namesize = 0;
    if (!from_hex8(p + 54, &filesize)) return 0; /* c_filesize */
    if (!from_hex8(p + 94, &namesize)) return 0; /* c_namesize */

    const uint8_t *name = p + 110;
    if (name + namesize > end) return 0;

    const uint8_t *filedata = p + align4(110u + (size_t)namesize);
    if (filedata + filesize > end) return 0;

    /* namesize includes the NUL terminator */
    const size_t namelen = namesize ? (size_t)namesize - 1 : 0;
    if (namelen == 10 && memcmp(name, "TRAILER!!!", 10) == 0) return 0;

    /* Accept "flag" or "/flag" just in case. */
    int is_flag = (namelen == 4 && memcmp(name, "flag", 4) == 0) ||
                  (namelen == 5 && memcmp(name, "/flag", 5) == 0);

    if (is_flag) {
      size_t n = filesize;
      if (n >= outlen) n = outlen - 1;
      memcpy(out, filedata, n);
      out[n] = '\0';

      /* Trim trailing newline(s). */
      while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) {
        out[n - 1] = '\0';
        n--;
      }
      return 1;
    }

    p = filedata + align4((size_t)filesize);
  }

  return 0;
}

int main(void) {
  initialise_monitor_handles();
  setvbuf(stdout, NULL, _IONBF, 0);

  char expected[64];
  char got[256];

  deobfuscate_flag(expected, sizeof(expected));

  if (!read_flag_from_embedded_fs(got, sizeof(got))) {
    puts("Failed to read /flag from embedded filesystem");
    exit(1);
  }

  const size_t elen = strlen(expected);
  const size_t glen = strlen(got);

  const uint32_t ecrc = crc32_ieee((const uint8_t *)expected, elen);
  const uint32_t gcrc = crc32_ieee((const uint8_t *)got, glen);

  if (elen == glen && ecrc == gcrc) {
    puts("Correct checksum in /flag file!");
    exit(0);
  }

  puts("Wrong checksum in /flag file!");
  exit(1);
}

