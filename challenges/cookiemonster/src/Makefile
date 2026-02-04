CFLAGS ?= -O0 -g -fno-stack-protector -no-pie -Wall -Wextra
LDFLAGS ?=

all: cookiemonster

cookiemonster: cookiemonster.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f cookiemonster

.PHONY: all clean

