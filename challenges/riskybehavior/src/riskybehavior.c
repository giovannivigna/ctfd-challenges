#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int mod95(int x) {
  x %= 95;
  if (x < 0) x += 95;
  return x;
}

/*
 * Reversible printable-only transform over ASCII 0x20..0x7e (95 chars).
 * Intended to be annoying-but-not-hard to reverse in a debugger.
 *
 * Encoding (conceptually):
 *   x = plain[i] - 32
 *   x = (x + key[i%k] + prev) mod 95
 *   x = (x*12 + (i*7+13)) mod 95
 *   prev = x
 *   out[i] = x + 32
 *
 * Decoding does the inverse; note prev uses the previous encoded symbol.
 */
static void deobfuscate_printable(const char *in, char *out, size_t n) {
  static const uint8_t key[] = "riskybehavior";
  const int inv12 = 8; /* 12*8 == 1 (mod 95) */
  int prev = 8;

  for (size_t i = 0; i < n; i++) {
    int y = (unsigned char)in[i] - 32; /* encoded symbol, 0..94 */
    int add = (int)((i * 7u + 13u) % 95u);
    int t = mod95(inv12 * (y - add));
    int x = mod95(t - (int)key[i % (sizeof(key) - 1)] - prev);
    out[i] = (char)(x + 32);
    prev = y;
  }
  out[n] = '\0';
}

static int read_line(char *buf, size_t buflen) {
  if (!fgets(buf, (int)buflen, stdin)) return 0;
  size_t n = strcspn(buf, "\r\n");
  buf[n] = '\0';
  return 1;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  /* Obfuscated form of: ictf{to_risc_or_not_to_risc} */
  static const char obf[] = "i/>P:j_clRy`L#0g^N9G;?SutMY@";
  char want[128];
  char got[128];

  puts("== riskybehavior ==");
  puts("I have an obfuscated string for you.");
  puts("It only contains printable characters.");
  printf("obfuscated: %s\n", obf);
  puts("");
  puts("Enter the deobfuscated string:");
  printf("> ");

  if (!read_line(got, sizeof(got))) return 1;

  deobfuscate_printable(obf, want, strlen(obf));

  if (strcmp(got, want) == 0) {
    puts("All right! You guessed that risky flag!");
    return 0;
  }

  puts("Nope.");
  return 1;
}

