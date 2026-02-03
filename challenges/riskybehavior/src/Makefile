CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -fno-plt
LDFLAGS ?=

BIN := riskybehavior
SRC := riskybehavior.c

# Patch ELF e_ident so common qemu-binfmt rules won't match.
# (Many binfmt_misc registrations require EI_ABIVERSION==0.)
PATCH_BINFMT ?= 1
EI_OSABI ?= 0
EI_ABIVERSION ?= 1

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@if [ "$(PATCH_BINFMT)" != "0" ]; then \
		EI_OSABI="$(EI_OSABI)" EI_ABIVERSION="$(EI_ABIVERSION)" sh ./patch_binfmt.sh "$@"; \
	fi

clean:
	rm -f $(BIN)

