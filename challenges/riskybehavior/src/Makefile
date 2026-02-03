TARGET ?= riscv64-linux-gnu

# GNU Make sets a built-in default `CC=cc`; detect that and default to clang.
ifeq ($(origin CC),default)
CC := clang
endif
ifeq ($(origin LD),default)
LD := $(TARGET)-ld
endif

# Build a Linux RISC-V ELF without requiring a target libc/sysroot.
# `riskybehavior.c` is freestanding and does raw syscalls.
CFLAGS ?= -O2 -g -Wall -Wextra -ffreestanding -fno-builtin -fno-stack-protector
CFLAGS += --target=$(TARGET) -march=rv64gc -mabi=lp64d

# Link with the target linker (binutils), using our own `_start`.
LDFLAGS ?= -e _start

BIN := riskybehavior
SRC := riskybehavior.c
OBJ := riskybehavior.o

# Patch ELF e_ident so common qemu-binfmt rules won't match.
# (Many binfmt_misc registrations require EI_ABIVERSION==0.)
PATCH_BINFMT ?= 1
EI_OSABI ?= 0
EI_ABIVERSION ?= 1

.PHONY: all clean

all: $(BIN)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $<
	@if [ "$(PATCH_BINFMT)" != "0" ]; then \
		EI_OSABI="$(EI_OSABI)" EI_ABIVERSION="$(EI_ABIVERSION)" sh ./patch_binfmt.sh "$@"; \
	fi

clean:
	rm -f $(BIN) $(OBJ)

