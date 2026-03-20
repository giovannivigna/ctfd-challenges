SERVICE=thatotherthing
CFLAGS ?= -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-pie -no-pie
LDFLAGS ?= -static -Wl,--build-id=none

all:
	gcc $(CFLAGS) ${SERVICE}.c -o ${SERVICE} $(LDFLAGS)

clean:
	rm -fr ${SERVICE}
