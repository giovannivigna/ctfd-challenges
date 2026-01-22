## Summary

The service is a tiny "firmware" loader.

It tries to read two partition files from:

- `/home/challenge/rw/part0.bin`
- `/home/challenge/rw/part1.bin`

If they do not exist yet, the program lets you provide their contents as a **hex string** and writes them into the `rw` directory.

It then computes a 1-byte checksum for each file:

- checksum = (sum of all bytes) mod 256

If **part0 checksum is 0xCA and part1 checksum is 0xFE**, it deobfuscates and prints the flag.

## Solution

Make part0 checksum equal to 0xCA and part1 checksum equal to 0xFE.

The easiest payload is a single `CA` byte for part0 and a single `FE` byte for part1.

## Exploit

Run `./writeup/exploit` to connect and send `CA` and `FE`.

