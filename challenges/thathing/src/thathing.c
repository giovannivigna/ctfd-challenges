#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define INPUT_LEN 24

static inline uint8_t rotl8(uint8_t x, unsigned r) {
    r &= 7u;
    return (uint8_t)((uint8_t)(x << r) | (uint8_t)(x >> ((8u - r) & 7u)));
}

static inline uint8_t rotr8(uint8_t x, unsigned r) {
    r &= 7u;
    return (uint8_t)((uint8_t)(x >> r) | (uint8_t)(x << ((8u - r) & 7u)));
}

static const uint8_t TARGET_X[INPUT_LEN] = {
    0x14, 0xc5, 0x73, 0xb6, 0x42, 0xf1, 0xc6, 0xa4,
    0x10, 0xc1, 0x86, 0xa9, 0x29, 0xaf, 0x05, 0x18,
    0xc4, 0xde, 0x47, 0x13, 0x09, 0x03, 0xcd, 0x4d
};

static const uint16_t TARGET_ST16[4] = { 0xb51a, 0x8c24, 0x9fd9, 0x8ef2 };
static const uint32_t FINAL_ST = 0x0f948ef2u;

int validate(const uint8_t *s, size_t n) {
    if (n != INPUT_LEN) return 0;

    uint32_t st = 0xC0FFEE13u;

    for (size_t i = 0; i < INPUT_LEN; i++) {
        uint8_t a = s[i];
        if (a < 0x21u || a > 0x7eu) return 0;

        uint8_t b = s[(i + 7u) % INPUT_LEN];
        uint8_t c = s[(i + 13u) % INPUT_LEN];

        uint8_t x = (uint8_t)(a ^ (uint8_t)(0xA5u + (uint8_t)(11u * i)));
        x = (uint8_t)(x + rotl8(b, (unsigned)i));
        x ^= rotr8(c, (unsigned)i + 3u);
        x = (uint8_t)(x * (uint8_t)(0x3Du ^ (uint8_t)(7u * i)));
        x ^= (uint8_t)((st >> ((unsigned)(i & 3u) * 8u)) & 0xffu);

        st = (st + 0x9e3779b9u);
        st ^= (uint32_t)x * 0x45d9f3bu;
        st ^= (st >> 16);

        if (x != TARGET_X[i]) return 0;

        if ((i % 6u) == 5u) {
            if ((st & 0xffffu) != (uint32_t)TARGET_ST16[i / 6u]) return 0;
        }
    }

    return st == FINAL_ST;
}

#ifndef THATHING_NO_MAIN
static void print_flag(void) {
    FILE *fp = fopen("/flag", "r");
    if (!fp) {
        puts("(flag missing)");
        return;
    }

    char buf[256];
    if (fgets(buf, sizeof(buf), fp)) {
        fputs(buf, stdout);
    }
    fclose(fp);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("Give me that thing.");
    printf("Input (%d chars): ", INPUT_LEN);

    char line[256];
    if (!fgets(line, sizeof(line), stdin)) {
        puts("No input.");
        return 1;
    }

    char *p = strchr(line, 10);
    if (p) *p = 0;

    size_t len = strlen(line);
    if (len != INPUT_LEN) {
        puts("Nope.");
        return 0;
    }

    if (validate((const uint8_t *)line, len)) {
        puts("OK.");
        print_flag();
    } else {
        puts("Nope.");
    }

    return 0;
}

#endif
