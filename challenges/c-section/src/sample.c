#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void die(const char *msg) {
  perror(msg);
  _exit(1);
}

static void write_all(const void *buf, size_t n) {
  const unsigned char *p = (const unsigned char *)buf;
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(STDOUT_FILENO, p + off, n - off);
    if (w < 0) die("write");
    off += (size_t)w;
  }
}

static void b64_emit_quad(const unsigned char in[3], int len, size_t *col) {
  static const char tbl[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  unsigned a = in[0];
  unsigned b = (len > 1) ? in[1] : 0;
  unsigned c = (len > 2) ? in[2] : 0;

  char out[4];
  out[0] = tbl[(a >> 2) & 0x3f];
  out[1] = tbl[((a & 0x3) << 4) | ((b >> 4) & 0xf)];
  out[2] = (len > 1) ? tbl[((b & 0xf) << 2) | ((c >> 6) & 0x3)] : '=';
  out[3] = (len > 2) ? tbl[c & 0x3f] : '=';

  write_all(out, sizeof(out));
  *col += 4;
  if (*col >= 76) {
    write_all("\n", 1);
    *col = 0;
  }
}

static void dump_fd_base64(int fd) {
  unsigned char buf[4096];
  unsigned char tail[3];
  int tail_len = 0;
  size_t col = 0;

  while (1) {
    ssize_t r = read(fd, buf, sizeof(buf));
    if (r < 0) die("read");
    if (r == 0) break;

    size_t i = 0;
    if (tail_len > 0) {
      while (tail_len < 3 && i < (size_t)r) tail[tail_len++] = buf[i++];
      if (tail_len == 3) {
        b64_emit_quad(tail, 3, &col);
        tail_len = 0;
      }
    }

    while (i + 3 <= (size_t)r) {
      b64_emit_quad(buf + i, 3, &col);
      i += 3;
    }

    while (i < (size_t)r) tail[tail_len++] = buf[i++];
  }

  if (tail_len > 0) b64_emit_quad(tail, tail_len, &col);
  if (col != 0) write_all("\n", 1);
}

static int starts_with(const char *s, const char *pfx) {
  size_t n = strlen(pfx);
  return strncmp(s, pfx, n) == 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  puts("sample@c-infrastructure");
  puts("I can print files under /proc.");
  puts("Send paths (one per line). Ctrl-D to exit.");

  char *line = NULL;
  size_t cap = 0;
  while (1) {
    fputs("> ", stdout);
    ssize_t n = getline(&line, &cap, stdin);
    if (n <= 0) break;

    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    if (n == 0) continue;

    if (!starts_with(line, "/proc/")) {
      puts("nope (only /proc/*)");
      continue;
    }

    int fd = open(line, O_RDONLY);
    if (fd < 0) {
      printf("open failed: %s\n", strerror(errno));
      continue;
    }

    dump_fd_base64(fd);
    close(fd);
    write_all("\n", 1);
  }
  free(line);
  return 0;
}
