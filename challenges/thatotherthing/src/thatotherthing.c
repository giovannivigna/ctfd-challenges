#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define INPUT_LEN 32

static inline uint8_t rotl8(uint8_t x, unsigned r) {
    r &= 7u;
    return (uint8_t)((uint8_t)(x << r) | (uint8_t)(x >> ((8u - r) & 7u)));
}

static inline uint8_t rotr8(uint8_t x, unsigned r) {
    r &= 7u;
    return (uint8_t)((uint8_t)(x >> r) | (uint8_t)(x << ((8u - r) & 7u)));
}

static const uint8_t TARGET_X[INPUT_LEN] = {
    0x04, 0xc9, 0xc1, 0x64, 0x56, 0x5c, 0xf3, 0x0e,
    0x87, 0x4f, 0xb8, 0x76, 0xf0, 0x77, 0x0b, 0x86,
    0xe5, 0xd9, 0x72, 0x43, 0x16, 0x19, 0x44, 0xc0,
    0xed, 0xf0, 0xc5, 0x47, 0x3f, 0xc6, 0x16, 0xdd
};

static const uint16_t TARGET_ST16[4] = { 0xb796, 0x6a5a, 0xe09e, 0xb7e3 };
static const uint32_t FINAL_ST = 0xd409b7e3u;

__attribute__((noinline, used))
int validate(const uint8_t *s, size_t n) {
    uint32_t ok = (n == INPUT_LEN);
    uint32_t st = 0x13579bdfu;

    for (size_t i = 0; i < INPUT_LEN; i++) {
        uint8_t a = s[i];
        ok &= (uint32_t)(a >= 0x21u);
        ok &= (uint32_t)(a <= 0x7eu);

        uint8_t b = s[(i + 5u) % INPUT_LEN];
        uint8_t c = s[(i + 17u) % INPUT_LEN];

        uint8_t x = (uint8_t)(a ^ (uint8_t)(0x5au + (uint8_t)(9u * i)));
        x = (uint8_t)(x + rotl8(b, (unsigned)i));
        x ^= rotr8(c, (unsigned)i + 3u);
        x = (uint8_t)(x * (uint8_t)(0xd3u - (uint8_t)(7u * i)));
        x ^= (uint8_t)((st >> ((unsigned)(i & 3u) * 8u)) & 0xffu);

        st ^= (uint32_t)x * 0x9e3779b1u;
        st += 0x7f4a7c15u;

        ok &= (uint32_t)(x == TARGET_X[i]);
        if ((i % 8u) == 7u) {
            ok &= (uint32_t)((st & 0xffffu) == (uint32_t)TARGET_ST16[i / 8u]);
        }
    }

    ok &= (uint32_t)(st == FINAL_ST);
    return (int)ok;
}

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

    puts("Give me that other thing.");
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

