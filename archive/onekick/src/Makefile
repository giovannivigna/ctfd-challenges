SERVICE=onekick

all:
	gcc -Wall -O0 -g -fno-omit-frame-pointer -D_FORTIFY_SOURCE=0 \
		-fno-pie -no-pie -z norelro \
		-fstack-protector-strong ${SERVICE}.c -o ${SERVICE}
clean:
	rm -fr ${SERVICE}
