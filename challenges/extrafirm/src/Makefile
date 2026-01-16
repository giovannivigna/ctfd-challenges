CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wshadow -Wpedantic
LDFLAGS ?=

all: extrafirm

extrafirm: extrafirm.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	strip -s $@ || true

clean:
	rm -f extrafirm
