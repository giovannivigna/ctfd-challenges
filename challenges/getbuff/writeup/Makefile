
asm:
	nasm -f elf32 shellcode.asm -o shellcode.o
	ld -m elf_i386 -s -o shellcode shellcode.o
	objdump -d ./shellcode | grep '^ ' | cut -f2 -d: | cut -f1-6 -d' ' | tr -d ' \t' | sed 's/.\{2\}/\\x&/g' | tr -d '\n'; echo ""
bin:
	gcc -m32 -Wall -O0 -g -fno-omit-frame-pointer -Wno-deprecated-declarations -D_FORTIFY_SOURCE=0 \
		-fno-pie -Wno-format -Wno-format-security -z norelro -z execstack \
		-fno-stack-protector -mpreferred-stack-boundary=2 shellcode.c -o shellcode
