CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wshadow -Wpedantic
LDFLAGS ?=

all: notsofirm

notsofirm: notsofirm.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	strip -s $@ || true

clean:
	rm -f notsofirm

