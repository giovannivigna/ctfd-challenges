#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *FILE0 = "/home/challenge/rw/part0.bin";
static const char *FILE1 = "/home/challenge/rw/part1.bin";

// Obfuscated "ictf{ThisIsNotSoFirmCode}\0" (plain XOR with KEY)
static const uint8_t KEY[8] = {'N', 'o', 't', 'S', 'o', 'K', 'e', 'y'};
static const uint8_t OBF_FLAG[] = {
    0x27, 0x0c, 0x00, 0x35, 0x14, 0x1f, 0x0d, 0x10, 0x3d, 0x26, 0x07, 0x1d, 0x00,
    0x3f, 0x36, 0x16, 0x08, 0x06, 0x06, 0x3e, 0x2c, 0x24, 0x01, 0x1c, 0x33, 0x6f,
};

__attribute__((noinline)) void strip_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

__attribute__((noinline)) int hexval(int c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}

__attribute__((noinline)) bool parse_hex_bytes(const char *hex, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    if (!hex) return false;
    size_t n = strlen(hex);
    if ((n & 1u) != 0) return false;
    if (n > 1024) return false; // cap: 512 bytes

    size_t len = n / 2;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) return false;

    for (size_t i = 0; i < len; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return false;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }

    *out = buf;
    *out_len = len;
    return true;
}

__attribute__((noinline)) bool write_file(const char *path, const uint8_t *buf, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            close(fd);
            return false;
        }
        off += (size_t)n;
    }
    close(fd);
    return true;
}

__attribute__((noinline)) bool checksum_file(const char *path, uint8_t *sum_out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    uint8_t sum = 0;
    uint8_t buf[512];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) {
            close(fd);
            return false;
        }
        for (ssize_t i = 0; i < n; i++) sum = (uint8_t)(sum + buf[i]);
    }
    close(fd);
    *sum_out = sum;
    return true;
}

__attribute__((noinline)) void maybe_create_file_from_input(const char *path, const char *label) {
    if (access(path, R_OK) == 0) return;

    dprintf(STDOUT_FILENO, "Missing %s.\n", label);
    dprintf(STDOUT_FILENO, "Send hex bytes to write %s (even length, max 1024 hex chars):\n", label);

    char *line = NULL;
    size_t cap = 0;
    ssize_t got = getline(&line, &cap, stdin);
    if (got < 0) {
        free(line);
        return;
    }
    strip_newline(line);

    uint8_t *buf = NULL;
    size_t len = 0;
    if (!parse_hex_bytes(line, &buf, &len)) {
        dprintf(STDOUT_FILENO, "Bad hex. Keeping %s missing.\n", label);
        free(line);
        return;
    }
    (void)write_file(path, buf, len);
    free(buf);
    free(line);
}

__attribute__((noinline)) void send_authorization_key(void) {
    char out[sizeof(OBF_FLAG)];
    for (size_t i = 0; i < sizeof(OBF_FLAG); i++) {
        uint8_t x = OBF_FLAG[i];
        x ^= KEY[i % sizeof(KEY)];
        out[i] = (char)x;
    }
    out[sizeof(out) - 1] = '\0';
    dprintf(STDOUT_FILENO, "%s\n", out);
}

int main(void) {
    dprintf(STDOUT_FILENO, "NOTSOFW minimal loader\n");
    dprintf(STDOUT_FILENO, "Reading partitions...\n");

    // "Attempts to read two files": if they don't exist, allow the user to provide them.
    maybe_create_file_from_input(FILE0, "part0.bin");
    maybe_create_file_from_input(FILE1, "part1.bin");

    uint8_t s0 = 0, s1 = 0;
    if (!checksum_file(FILE0, &s0) || !checksum_file(FILE1, &s1)) {
        dprintf(STDOUT_FILENO, "Partition read failed.\n");
        return 1;
    }

    dprintf(STDOUT_FILENO, "Checksum(part0) = 0x%02x\n", s0);
    dprintf(STDOUT_FILENO, "Checksum(part1) = 0x%02x\n", s1);

    if (s0 != 0xCA || s1 != 0xFE) {
        dprintf(STDOUT_FILENO, "Integrity check failed.\n");
        return 1;
    }

    send_authorization_key();
    return 0;
}

