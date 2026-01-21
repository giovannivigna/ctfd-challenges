## Summary

The service is a tiny "firmware" loader.

It tries to read two partition files from:

- `/home/challenge/rw/part0.bin`
- `/home/challenge/rw/part1.bin`

If they do not exist yet, the program lets you provide their contents as a **hex string** and writes them into the `rw` directory.

It then computes a 1-byte checksum for each file:

- checksum = (sum of all bytes) mod 256

If **both checksums are 0**, it deobfuscates and prints the flag.

## Solution

Make both checksums equal to 0.

The easiest payload is a single `00` byte for each partition (sum = 0).

## Exploit

Run `./writeup/exploit` to connect and send `00` twice.

