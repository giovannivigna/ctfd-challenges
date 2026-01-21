#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// ---- "Firmware-ish" metadata (just to look like one) ------------------------

struct fw_header {
    char magic[8];      // "EXTRAFW\0"
    uint32_t version;   // 0x00010001
    uint32_t hdr_len;   // sizeof(struct fw_header)
    uint32_t image_len; // not real
    uint32_t flags;     // not real
    uint8_t salt[16];
    uint8_t reserved[32];
};

__attribute__((section(".fw_hdr"), used))
static const struct fw_header g_fw = {
    .magic = { 'E','X','T','R','A','F','W','\0' },
    .version = 0x00010001u,
    .hdr_len = (uint32_t)sizeof(struct fw_header),
    .image_len = 0x00123456u,
    .flags = 0x000000A5u,
    .salt = {
        0x21,0x43,0x65,0x87,0xA9,0xCB,0xED,0x0F,
        0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE
    },
    .reserved = {0},
};

__attribute__((section(".fw_pad"), used))
static const uint8_t g_pad[4096] = {
    // Not random, just noisy enough to look "blob-ish"
    0xA5,0x5A,0xC3,0x3C,0x96,0x69,0xF0,0x0F,0x1B,0xB1,0x77,0xEE,
};

// ---- XOR-obfuscated file paths ---------------------------------------------

static void deobf_path(const uint8_t *in, size_t n, char *out) {
    const uint8_t k = 0x5C;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(in[i] ^ k ^ (uint8_t)(i * 13u));
    }
    out[n] = '\0';
}

// Plain paths (for reference):
//  /home/challenge/rw/boot.cfg
//  /home/challenge/rw/keys.bin
//  /home/challenge/rw/region.dat
//  /home/challenge/rw/manifest.sig

static const uint8_t g_p0[] = {
    0x73,0x39,0x29,0x16,0x0d,0x32,0x71,0x6f,0x55,0x45,0xb2,0xb6,0xae,0x92,0x8f,0xb0,
    0xfe,0xf6,0x99,0xc9,0x37,0x22,0x36,0x59,0x07,0x7f,0x69
};
static const uint8_t g_p1[] = {
    0x73,0x39,0x29,0x16,0x0d,0x32,0x71,0x6f,0x55,0x45,0xb2,0xb6,0xae,0x92,0x8f,0xb0,
    0xfe,0xf6,0x99,0xc0,0x3d,0x34,0x31,0x59,0x06,0x70,0x60
};
static const uint8_t g_p2[] = {
    0x73,0x39,0x29,0x16,0x0d,0x32,0x71,0x6f,0x55,0x45,0xb2,0xb6,0xae,0x92,0x8f,0xb0,
    0xfe,0xf6,0x99,0xd9,0x3d,0x2a,0x2b,0x18,0x0a,0x37,0x6a,0x62,0x44
};
static const uint8_t g_p3[] = {
    0x73,0x39,0x29,0x16,0x0d,0x32,0x71,0x6f,0x55,0x45,0xb2,0xb6,0xae,0x92,0x8f,0xb0,
    0xfe,0xf6,0x99,0xc6,0x39,0x23,0x2b,0x11,0x01,0x6a,0x7a,0x2d,0x43,0x4c,0xbd
};

// ---- 10-byte checksum functions (4 different ones) -------------------------

static inline uint8_t rol8(uint8_t x, unsigned r) {
    r &= 7u;
    return (uint8_t)((x << r) | (x >> (8u - r)));
}

static void checksum_a(int fd, uint8_t out[10]) {
    uint8_t s[10] = {0x42,0x11,0x9c,0x07,0x58,0xe1,0x2d,0xb6,0x73,0x0a};
    uint8_t buf[256];
    size_t idx = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) break;
        for (ssize_t i = 0; i < n; i++, idx++) {
            uint8_t b = buf[i];
            s[idx % 10] = (uint8_t)(s[idx % 10] + (uint8_t)(b ^ (uint8_t)idx) + 0x3Du);
            s[(idx + 3) % 10] ^= rol8(b, (unsigned)((idx % 5) + 1));
            s[(idx + 7) % 10] = (uint8_t)(s[(idx + 7) % 10] + (uint8_t)(b * 3u));
        }
    }
    memcpy(out, s, 10);
}

static void checksum_b(int fd, uint8_t out[10]) {
    uint32_t a = 0x13579BDFu;
    uint32_t b = 0x2468ACE0u;
    uint16_t c = 0xBEEFu;
    uint8_t buf[256];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) break;
        for (ssize_t i = 0; i < n; i++) {
            uint8_t x = buf[i];
            a = (a + x + 0x9Eu) * 0x45D9F3Bu;
            a ^= (a >> 16);
            b ^= (uint32_t)(x + (uint8_t)a);
            b = (b << 3) | (b >> (32 - 3));
            c = (uint16_t)((c << 5) ^ (c >> 3) ^ (uint16_t)(x * 257u));
        }
    }
    out[0] = (uint8_t)(a);
    out[1] = (uint8_t)(a >> 8);
    out[2] = (uint8_t)(a >> 16);
    out[3] = (uint8_t)(a >> 24);
    out[4] = (uint8_t)(b);
    out[5] = (uint8_t)(b >> 8);
    out[6] = (uint8_t)(b >> 16);
    out[7] = (uint8_t)(b >> 24);
    out[8] = (uint8_t)(c);
    out[9] = (uint8_t)(c >> 8);
}

static void checksum_c(int fd, uint8_t out[10]) {
    uint64_t s = 0x9E3779B97F4A7C15ull;
    uint16_t t = 0x1234u;
    uint8_t buf[256];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) break;
        for (ssize_t i = 0; i < n; i++) {
            uint64_t x = (uint64_t)buf[i] + 0x100ull + (uint64_t)(t & 0xFFu);
            s ^= x + (s << 7) + (s >> 3);
            s ^= (s << 13);
            s ^= (s >> 7);
            s ^= (s << 17);
            t = (uint16_t)((t * 33u) ^ (uint16_t)buf[i]);
        }
    }
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(s >> (8 * i));
    out[8] = (uint8_t)(t);
    out[9] = (uint8_t)(t >> 8);
}

static uint16_t crc16_ccitt_update(uint16_t crc, uint8_t data) {
    crc ^= (uint16_t)data << 8;
    for (int i = 0; i < 8; i++) {
        if (crc & 0x8000) crc = (uint16_t)((crc << 1) ^ 0x1021u);
        else crc <<= 1;
    }
    return crc;
}

static void checksum_d(int fd, uint8_t out[10]) {
    uint16_t crc = 0xFFFFu;
    uint32_t x = 0xCAFEBABEu;
    uint32_t y = 0x0BADC0DEu;
    uint8_t buf[256];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) break;
        for (ssize_t i = 0; i < n; i++) {
            uint8_t b = buf[i];
            crc = crc16_ccitt_update(crc, b);
            x ^= (uint32_t)(b + (uint8_t)crc);
            x *= 0x27D4EB2Du;
            y += (uint32_t)(rol8(b, (unsigned)(b & 7u)) ^ (uint8_t)x);
            y = (y << 9) | (y >> (32 - 9));
        }
    }
    out[0] = (uint8_t)x;
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
    out[4] = (uint8_t)y;
    out[5] = (uint8_t)(y >> 8);
    out[6] = (uint8_t)(y >> 16);
    out[7] = (uint8_t)(y >> 24);
    out[8] = (uint8_t)crc;
    out[9] = (uint8_t)(crc >> 8);
}

// ---- expected 40-byte value (also the obfuscated flag) ----------------------

struct expected_blob {
    char tag[8];      // "FWCMPv1"
    uint8_t value[40];
};

__attribute__((used))
static const struct expected_blob g_expected = {
    .tag = {'F','W','C','M','P','v','1','\0'},
    // Generated from flag by src/mkvalue.py (default flag: ictf{extrafirm_xor_checksums})
    .value = {
        0xaa,0x19,0x61,0x8f,0x30,0x79,0xf8,0x97,0xb0,0x33,
        0x66,0xac,0x33,0x59,0xe2,0x9f,0x85,0x13,0x67,0x84,
        0x08,0x42,0xf4,0x9b,0xbe,0x7a,0x15,0xe9,0x4b,0x2d,
        0x90,0xfe,0xc3,0x7a,0x15,0xe9,0x4b,0x2d,0x90,0xfe
    }
};

// ---- flag deobfuscation -----------------------------------------------------

static const uint8_t g_key[8] = {0xC3,0x7A,0x15,0xE9,0x4B,0x2D,0x90,0xFE};

void extract_authorization_key(const uint8_t in[40], uint8_t out[40]) {
    for (size_t i = 0; i < 40; i++) {
        out[i] = (uint8_t)(in[i] ^ g_key[i % (sizeof g_key)]);
    }
}

// ---- helpers ----------------------------------------------------------------

static int open_or_neg1(const char *path) {
    int fd = open(path, O_RDONLY);
    return fd;
}

static bool read_and_checksum(const uint8_t *obfp, size_t obfp_len,
                              void (*fn)(int, uint8_t[10]),
                              uint8_t out10[10]) {
    char path[128];
    deobf_path(obfp, obfp_len, path);

    int fd = open_or_neg1(path);
    if (fd < 0) {
        // Deterministic but obviously "bad"
        for (int i = 0; i < 10; i++) out10[i] = (uint8_t)(0xEEu ^ (uint8_t)i);
        return false;
    }

    fn(fd, out10);
    close(fd);
    return true;
}

static bool ct_memeq_40(const uint8_t a[40], const uint8_t b[40]) {
    uint8_t acc = 0;
    for (size_t i = 0; i < 40; i++) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

int main(void) {
    // A couple lines to resemble a firmware console
    dprintf(STDOUT_FILENO, "EXTRAFW bootloader v%u.%u\n", (g_fw.version >> 16) & 0xFFFFu, g_fw.version & 0xFFFFu);
    dprintf(STDOUT_FILENO, "Validating partitions...\n");

    uint8_t computed[40];
    bool ok0 = read_and_checksum(g_p0, sizeof g_p0, checksum_a, &computed[0]);
    bool ok1 = read_and_checksum(g_p1, sizeof g_p1, checksum_b, &computed[10]);
    bool ok2 = read_and_checksum(g_p2, sizeof g_p2, checksum_c, &computed[20]);
    bool ok3 = read_and_checksum(g_p3, sizeof g_p3, checksum_d, &computed[30]);

    if (!(ok0 && ok1 && ok2 && ok3)) {
        dprintf(STDOUT_FILENO, "WARN: missing partition file(s)\n");
    }

    if (!ct_memeq_40(computed, g_expected.value)) {
        dprintf(STDOUT_FILENO, "Integrity check failed.\n");
        return 1;
    }

    uint8_t flag40[40];
    extract_authorization_key(g_expected.value, flag40);

    // Print as a bounded C string (flag is < 40 bytes, zero-padded).
    char out[41];
    memcpy(out, flag40, 40);
    out[40] = '\0';
    dprintf(STDOUT_FILENO, "%s\n", out);
    return 0;
}

