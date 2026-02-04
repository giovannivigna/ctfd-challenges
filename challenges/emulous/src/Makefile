TARGET ?= powerpc-linux-gnu

BIN := emulous
SRC := emulous.c

# Patch ELF e_ident so common qemu-binfmt rules won't match.
PATCH_BINFMT ?= 1
EI_OSABI ?= 0
EI_ABIVERSION ?= 1

.PHONY: all clean docker-build

all: $(BIN)

$(BIN): $(SRC) patch_binfmt.sh
	@command -v $(TARGET)-gcc >/dev/null 2>&1 || { \
		echo "error: missing $(TARGET)-gcc. Use 'make docker-build' to build via Docker."; \
		exit 1; \
	}
	$(TARGET)-gcc -O2 -Wall -Wextra -o $@ $(SRC)
	$(TARGET)-strip --strip-all $@
	@if [ "$(PATCH_BINFMT)" != "0" ]; then \
		EI_OSABI="$(EI_OSABI)" EI_ABIVERSION="$(EI_ABIVERSION)" sh ./patch_binfmt.sh "$@"; \
	fi

docker-build:
	docker run --rm -t \
	  -v "$$(pwd):/work" -w /work \
	  debian:stable-slim sh -eu -c '\
	    apt-get update; \
	    apt-get install -y --no-install-recommends make ca-certificates gcc-powerpc-linux-gnu libc6-dev-powerpc-cross binutils-powerpc-linux-gnu; \
	    $(TARGET)-gcc -O2 -Wall -Wextra -o $(BIN) $(SRC); \
	    $(TARGET)-strip --strip-all $(BIN); \
	    EI_OSABI="$(EI_OSABI)" EI_ABIVERSION="$(EI_ABIVERSION)" sh ./patch_binfmt.sh "$(BIN)"; \
	  '

clean:
	rm -f $(BIN)

