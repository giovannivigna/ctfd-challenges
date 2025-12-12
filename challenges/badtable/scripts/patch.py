import pwn
import sys

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <filename> <output>")
elf = pwn.ELF(sys.argv[1])

# Find the address of the 'timeout' global variable
timeout_addr = elf.symbols['timeout'] 

# Patch the 'timeout' variable with a new value
elf.write(timeout_addr, pwn.p32(0x0))  

elf.save(sys.argv[2])

print(f"Binary {sys.argv[1]} patched into {sys.argv[2]}")