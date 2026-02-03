/*
 * This challenge is intentionally shipped as a foreign-architecture Linux ELF.
 *
 * To keep the build self-contained (no target sysroot / libc required), this
 * program is "freestanding" and performs Linux syscalls directly (read/write/exit).
 *
 * It implements a reversible printable-only transform and checks whether the
 * user can deobfuscate the provided string.
 */

typedef unsigned long size_t;
typedef unsigned char uint8_t;

static inline long sys_write(long fd, const void *buf, long len) {
  register long a0 asm("a0") = fd;
  register long a1 asm("a1") = (long)buf;
  register long a2 asm("a2") = len;
  register long a7 asm("a7") = 64; /* __NR_write (riscv64) */
  asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
  return a0;
}

static inline long sys_read(long fd, void *buf, long len) {
  register long a0 asm("a0") = fd;
  register long a1 asm("a1") = (long)buf;
  register long a2 asm("a2") = len;
  register long a7 asm("a7") = 63; /* __NR_read (riscv64) */
  asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
  return a0;
}

__attribute__((noreturn)) static inline void sys_exit(int code) {
  register long a0 asm("a0") = code;
  register long a7 asm("a7") = 93; /* __NR_exit (riscv64) */
  asm volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
  __builtin_unreachable();
}

static size_t c_strlen(const char *s) {
  size_t n = 0;
  while (s[n] != '\0') n++;
  return n;
}

static int c_strcmp(const char *a, const char *b) {
  while (*a && *b && *a == *b) {
    a++;
    b++;
  }
  return (unsigned char)*a - (unsigned char)*b;
}

static void write_str(const char *s) {
  (void)sys_write(1, s, (long)c_strlen(s));
}

static void write_line(const char *s) {
  write_str(s);
  (void)sys_write(1, "\n", 1);
}

static int mod95(int x) {
  x %= 95;
  if (x < 0) x += 95;
  return x;
}

/*
 * Reversible printable-only transform over ASCII 0x20..0x7e (95 chars).
 * Decoding uses the previous encoded symbol as state.
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
  if (buflen < 2) return 0;
  long n = sys_read(0, buf, (long)(buflen - 1));
  if (n <= 0) return 0;

  size_t i = 0;
  while (i < (size_t)n && buf[i] != '\n' && buf[i] != '\r') i++;
  buf[i] = '\0';
  return 1;
}

static int main(void) {
  /* Obfuscated form of: ictf{to_risc_or_not_to_risc} */
  static const char obf[] = "i/>P:j_clRy`L#0g^N9G;?SutMY@";
  char want[128];
  char got[128];

  write_line("== riskybehavior ==");
  write_line("I have an obfuscated string for you.");
  write_line("It only contains printable characters.");
  write_str("obfuscated: ");
  write_line(obf);
  write_line("");
  write_line("Enter the deobfuscated string:");
  write_str("> ");

  if (!read_line(got, sizeof(got))) return 1;

  deobfuscate_printable(obf, want, c_strlen(obf));

  if (c_strcmp(got, want) == 0) {
    write_line("All right! You guessed that risky flag!");
    return 0;
  }

  write_line("Nope.");
  return 1;
}

void _start(void) {
  sys_exit(main());
}
