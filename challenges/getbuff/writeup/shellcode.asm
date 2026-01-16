section .data
    flag db '/flag',0

section .text
global _start

_start:
    ; open("/flag", O_RDONLY)
    mov eax, 5       ; syscall number for open()
    mov ebx, flag    ; pointer to the filename
    xor ecx, ecx     ; flags (O_RDONLY)
    int 0x80         ; call kernel

    ; read(fd, buf, 100)
    mov ebx, eax     ; file descriptor returned by open()
    mov eax, 3       ; syscall number for read()
    sub esp, 100     ; make space for file content
    mov ecx, esp     ; buffer
    mov edx, 100     ; number of bytes to read
    int 0x80         ; call kernel

    ; write(1, buf, 100)
    mov eax, 4       ; syscall number for write()
    mov ebx, 1       ; file descriptor (stdout)
    mov ecx, esp     ; buffer
    int 0x80         ; call kernel

    ; exit(0)
    mov eax, 1       ; syscall number for exit()
    xor ebx, ebx     ; exit code 0
    int 0x80         ; call kernel
