#include <stdint.h>
#include <stddef.h>

// Declare KLEE intrinsics without including klee headers.
void klee_make_symbolic(void *addr, size_t nbytes, const char *name);
void klee_assume(uintptr_t condition);
void klee_report_error(const char *file, int line, const char *message, const char *suffix);

int validate(const uint8_t *s, size_t n);

int main(void) {
    uint8_t in[24];
    klee_make_symbolic(in, sizeof(in), "in");

    for (size_t i = 0; i < sizeof(in); i++) {
        klee_assume(in[i] >= 0x21);
        klee_assume(in[i] <= 0x7e);
    }

    if (validate(in, sizeof(in))) {
        // Force KLEE to emit a testcase for the satisfying input.
        klee_report_error(__FILE__, __LINE__, "found", "found");
    }

    return 0;
}
