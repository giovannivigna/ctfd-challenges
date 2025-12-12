# Easy challenge, binary 64-bit: Overwrite in the BSS segment
# Source code provided
# Important: The flag must be owned by root (and be world-readable) but the service should run as a different user.

SERVICE=thisisbss

all:
	gcc -Wall -O0 -g -fno-omit-frame-pointer -Wno-deprecated-declarations -D_FORTIFY_SOURCE=0 \
		-fno-pie -Wno-format -Wno-format-security -z norelro -z execstack -fPIC \
		-fno-stack-protector ${SERVICE}.c -o ${SERVICE}
clean:
	rm -fr ${SERVICE} 
	
