## Summary

The provided file `src/extrafirm` is a 64-bit x86-64 ELF that pretends to be a firmware image.

It:

- Deobfuscates 4 file paths (XOR) and tries to open them.
- Runs 4 different routines that each output a **10-byte checksum**.
- Concatenates the 4 checksums into 40 bytes and compares them to an embedded 40-byte reference.
- If the comparison matches, it deobfuscates that 40-byte reference and prints it as the flag.

## Solution

The key observation is that the embedded 40-byte reference is **also the encrypted/obfuscated flag**.
You do not need the integrity check to pass; you can:

- Locate the `FWCMPv1` tag in the binary.
- Read the 40 bytes right after it.
- Apply the inverse transformation (rotate/xor) to recover the plaintext flag.

## Exploit

Run `./writeup/exploit` to extract and decrypt the flag from the binary.
