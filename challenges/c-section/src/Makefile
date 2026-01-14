CFLAGS := -O2 -Wall -Wextra -Wpedantic
LDFLAGS :=
OBJCOPY ?= objcopy
FLAG_PATH ?= /flag
SAMPLE_RAW := sample.raw

all: sample

$(SAMPLE_RAW): sample.c
	$(CC) $(CFLAGS) -o $@ $<

# Build the sample executable, then patch it with:
# - .cinfra.file     = "/flag\0"
# - .cinfra.contents = contents of /flag + "\0"
#
# This target is intended to run inside the container where $(FLAG_PATH) exists.
sample: $(SAMPLE_RAW)
	@set -e; \
	tmp_file=$$(mktemp); \
	tmp_contents=$$(mktemp); \
	printf "%s\0" "/flag" > "$$tmp_file"; \
	( cat "$(FLAG_PATH)"; printf "\0" ) > "$$tmp_contents"; \
	$(OBJCOPY) \
		--add-section .cinfra.file="$$tmp_file" \
		--set-section-flags .cinfra.file=contents,readonly \
		--add-section .cinfra.contents="$$tmp_contents" \
		--set-section-flags .cinfra.contents=contents,readonly \
		"$(SAMPLE_RAW)" "$@"; \
	rm -f "$$tmp_file" "$$tmp_contents"; \
	chmod 755 "$@"

clean:
	rm -f sample $(SAMPLE_RAW)
