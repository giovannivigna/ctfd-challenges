# Get buff

The service prints the address of a stack buffer (`buf`) and then reads user-controlled data into it without bounds checking.
If you overwrite the saved return address with the leaked `buf` address, you can redirect execution into your injected shellcode.

The program also enforces that the XOR of all received bytes is zero, so the payload must be constructed to satisfy this checksum.

The provided exploit:

- connects and parses the leaked buffer address
- builds i386 shellcode that reads `/flag` and prints it
- pads up to the real saved-EIP offset (1036 bytes) and overwrites the return address with the leaked buffer address
- flips one byte in the NOP sled so that the XOR checksum becomes 0 (without introducing a newline byte, which would truncate input)

