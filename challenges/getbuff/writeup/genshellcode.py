import pwn

pwn.context.arch = 'i386'  # Set architecture to 32-bit
shellcode = pwn.shellcraft.i386.linux.cat('/flag') # + pwn.shellcraft.i386.linux.exit() # Generate shellcode to cat /flag
assembled_shellcode = pwn.asm(shellcode)  # Assemble the shellcode

# Print out the generated shellcode in a format that can be copied
#print(pwn.enhex(assembled_shellcode))
p = pwn.run_shellcode(assembled_shellcode)
print(p.recvall())
# Format the shellcode as a C string
#formatted_shellcode = 'char code[] = "'
#for byte in assembled_shellcode:
#    formatted_shellcode += '\\x{:02x}'.format(byte)
#formatted_shellcode += '";'
# Print the formatted shellcode
#print(formatted_shellcode)