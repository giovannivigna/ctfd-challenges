CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -fno-plt
LDFLAGS ?=

BIN := moxiebox
SRC := moxiebox.c

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)

