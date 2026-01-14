#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void (*crypt_fn)(uint8_t *data, size_t len, const uint8_t *key, size_t key_len);

typedef struct Sleak {
    size_t key_len;
    uint8_t *key;
    size_t data_len;
    uint8_t *data;
    crypt_fn crypt;
    struct Sleak *next;
} Sleak;

static int get_maps_range_by_tag(const char *tag, uintptr_t *out_start, uintptr_t *out_end);
static int get_text_range(uintptr_t *out_start, uintptr_t *out_end);

static void die(const char *msg) {
    puts(msg);
    _exit(1);
}

static void *xcalloc(size_t n, size_t sz) {
    void *p = calloc(n, sz);
    if (!p) die("oom");
    return p;
}

static void *xmalloc(size_t sz) {
    void *p = malloc(sz);
    if (!p) die("oom");
    return p;
}

static ssize_t read_line(char *buf, size_t n) {
    if (n == 0) return -1;
    if (!fgets(buf, (int)n, stdin)) return -1;
    size_t l = strlen(buf);
    if (l && buf[l - 1] == '\n') buf[l - 1] = '\0';
    return (ssize_t)strlen(buf);
}

static uint64_t read_u64(const char *prompt) {
    char buf[128];
    printf("%s", prompt);
    if (read_line(buf, sizeof(buf)) < 0) die("bye");

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(buf, &end, 0);
    if (errno != 0) die("parse error");
    if (end == buf) die("parse error");
    while (*end) {
        if (!isspace((unsigned char)*end)) die("parse error");
        end++;
    }
    return (uint64_t)v;
}

static void crypt_xor(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) data[i] ^= key[i % key_len];
}

static void crypt_xor_rev(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) data[i] ^= key[(key_len - 1) - (i % key_len)];
}

static void hexdump(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static void print_node_details(Sleak *s, Sleak **head_addr_on_stack) {
    puts("---- sleak dump ----");
    printf("Node list @ %p (value=%p)\n", (void *)head_addr_on_stack,
           (void *)(head_addr_on_stack ? *head_addr_on_stack : NULL));

    uintptr_t stack_maps_start = 0, stack_maps_end = 0;
    if (get_maps_range_by_tag("[stack]", &stack_maps_start, &stack_maps_end)) {
        // Execution ID := (stack base from /proc/self/maps) - (&head_stack_slot)
        // This lets a client compute: stack_base = leaked_stack_slot_ptr + ExecutionID
        int64_t execution_id = (int64_t)(stack_maps_start - (uintptr_t)head_addr_on_stack);
        printf("Execution ID: %" PRId64 "\n", execution_id);
    } else {
        puts("Execution ID: (unavailable)");
    }

    printf("node @ %p\n", (void *)s);

    printf("  &node->key_len  = %p\n", (void *)&s->key_len);
    printf("  key_len         = %zu\n", s->key_len);
    printf("  &node->key      = %p\n", (void *)&s->key);
    printf("  key ptr value   = %p\n", (void *)s->key);
    if (s->key && s->key_len) {
        printf("  key bytes       = ");
        hexdump(s->key, s->key_len);
        puts("");
    }

    printf("  &node->data_len = %p\n", (void *)&s->data_len);
    printf("  data_len        = %zu\n", s->data_len);

    printf("  &node->data     = %p\n", (void *)&s->data);
    printf("  data ptr value  = %p\n", (void *)s->data);
    if (s->data && s->data_len) {
        printf("  data bytes      = ");
        hexdump(s->data, s->data_len);
        puts("");
    }

    printf("  &node->crypt    = %p\n", (void *)&s->crypt);
    printf("  crypt ptr value = %p\n", (void *)s->crypt);

    printf("  &node->next     = %p\n", (void *)&s->next);
    printf("  next ptr value  = %p\n", (void *)s->next);
    puts("--------------------");
}

static Sleak *get_nth(Sleak *head, size_t idx) {
    size_t i = 0;
    for (Sleak *cur = head; cur; cur = cur->next) {
        if (i == idx) return cur;
        i++;
    }
    return NULL;
}

static void add_node(Sleak **head) {
    uint64_t klen = read_u64("key length (1-256): ");
    if (klen == 0 || klen > 256) die("nope");

    uint64_t len = read_u64("data length (1-256): ");
    if (len == 0 || len > 256) die("nope");

    uint64_t which = read_u64("crypto (1=xor, 2=xor_rev): ");
    crypt_fn fn = (which == 2) ? crypt_xor_rev : crypt_xor;

    Sleak *n = (Sleak *)xcalloc(1, sizeof(*n));
    n->key_len = (size_t)klen;
    n->key = (uint8_t *)xmalloc(n->key_len);
    n->data_len = (size_t)len;
    n->data = (uint8_t *)xmalloc(n->data_len);
    n->crypt = fn;

    printf("key bytes (will be read raw-ish as a line): ");
    char kbuf[512];
    if (read_line(kbuf, sizeof(kbuf)) < 0) die("bye");
    size_t kinlen = strlen(kbuf);
    if (kinlen < n->key_len) {
        memset(n->key, 0, n->key_len);
        memcpy(n->key, kbuf, kinlen);
    } else {
        memcpy(n->key, kbuf, n->key_len);
    }

    printf("data bytes (will be read raw-ish as a line): ");
    char buf[512];
    if (read_line(buf, sizeof(buf)) < 0) die("bye");

    size_t inlen = strlen(buf);
    if (inlen < n->data_len) {
        memset(n->data, 0, n->data_len);
        memcpy(n->data, buf, inlen);
    } else {
        memcpy(n->data, buf, n->data_len);
    }

    n->crypt(n->data, n->data_len, n->key, n->key_len);

    n->next = *head;
    *head = n;

    puts("ok");
}

static void remove_node(Sleak **head) {
    uint64_t idx = read_u64("index: ");
    Sleak *prev = NULL;
    Sleak *cur = *head;
    size_t i = 0;
    while (cur) {
        if (i == idx) break;
        prev = cur;
        cur = cur->next;
        i++;
    }
    if (!cur) {
        puts("no such index");
        return;
    }

    if (prev) prev->next = cur->next;
    else *head = cur->next;

    if (cur->key) {
        memset(cur->key, 0, cur->key_len);
        free(cur->key);
    }
    if (cur->data) {
        memset(cur->data, 0, cur->data_len);
        free(cur->data);
    }
    memset(cur, 0, sizeof(*cur));
    free(cur);
    puts("removed");
}

static void print_node(Sleak **head, Sleak **head_addr_on_stack, Sleak **last_printed) {
    uint64_t idx = read_u64("index: ");
    Sleak *n = get_nth(*head, (size_t)idx);
    if (!n) {
        puts("no such index");
        return;
    }
    print_node_details(n, head_addr_on_stack);
    *last_printed = n;
}

static int get_maps_range_by_tag(const char *tag, uintptr_t *out_start, uintptr_t *out_end) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, tag)) continue;
        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            fclose(f);
            *out_start = start;
            *out_end = end;
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int get_text_range(uintptr_t *out_start, uintptr_t *out_end) {
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return 0;
    exe[n] = '\0';

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        // Example:
        // 555555554000-555555556000 r-xp 00001000 ... /path/to/exe
        if (!strstr(line, exe)) continue;
        if (!strstr(line, " r-xp ")) continue;

        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) == 2) {
            fclose(f);
            *out_start = start;
            *out_end = end;
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static void maybe_print_flag(Sleak **head_addr_on_stack, Sleak *last_printed) {
    if (!last_printed) {
        puts("You never printed a structure. No leaks, no luck.");
        return;
    }

    // Use only the VMA starts as shown in /proc/self/maps.
    uintptr_t stack_maps_start = 0, stack_maps_end = 0;
    if (!get_maps_range_by_tag("[stack]", &stack_maps_start, &stack_maps_end)) die("no stack?");

    uintptr_t heap_maps_start = 0, heap_maps_end = 0;
    if (!get_maps_range_by_tag("[heap]", &heap_maps_start, &heap_maps_end)) die("no heap?");

    uintptr_t text_maps_start = 0, text_maps_end = 0;
    if (!get_text_range(&text_maps_start, &text_maps_end)) die("no text?");

    uint64_t g_stack = read_u64("beginning of stack: ");
    uint64_t g_heap = read_u64("beginning of heap: ");
    uint64_t g_text = read_u64("beginning of .text: ");

    if ((uintptr_t)g_stack != stack_maps_start) {
        puts("stack: wrong");
        return;
    }
    if ((uintptr_t)g_heap != heap_maps_start) {
        puts("heap: wrong");
        return;
    }
    if ((uintptr_t)g_text != text_maps_start) {
        puts("text: wrong");
        return;
    }

    FILE *f = fopen("/flag", "rb");
    if (!f) die("no flag");
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    printf("This is the flag: %s\n", buf);
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    Sleak *head = NULL;              // head pointer lives on the stack
    Sleak *last_printed = NULL;      // also on the stack

    puts("sleak: create heap blobs, leak everything.");

    for (;;) {
        puts("");
        puts("1) create");
        puts("2) remove");
        puts("3) print");
        puts("4) quit");
        uint64_t c = read_u64("> ");

        if (c == 1) add_node(&head);
        else if (c == 2) remove_node(&head);
        else if (c == 3) print_node(&head, &head, &last_printed);
        else if (c == 4) break;
        else puts("?");
    }

    maybe_print_flag(&head, last_printed);

    return 0;
}

