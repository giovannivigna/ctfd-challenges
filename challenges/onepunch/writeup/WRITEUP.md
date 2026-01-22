# Onepunch

The challenge provides a binary that reads 16 bytes from stdin:
- First 8 bytes are treated as an address
- Second 8 bytes are written to that address
- Then the program calls `exit()`

The binary is compiled with:
- `-no-pie`: No Position Independent Executable (addresses are fixed)
- `-z norelro`: No Relocation Read-Only (GOT is writable)

There is a function `readflag()` that reads and prints `/flag`.

## Solution

Since the GOT is writable and addresses are fixed (no PIE), we can overwrite the GOT entry for `exit()` to point to `readflag()` instead.

1. Find the address of `exit@got.plt` (the GOT entry for exit):
   ```bash
   objdump -R onepunch | grep exit
   ```
   Or using readelf:
   ```bash
   readelf -r onepunch | grep exit
   ```

2. Find the address of `readflag()`:
   ```bash
   objdump -t onepunch | grep readflag
   ```
   Or using nm:
   ```bash
   nm onepunch | grep readflag
   ```

3. Construct the payload:
   - First 8 bytes: address of `exit@got.plt`
   - Second 8 bytes: address of `readflag()`

4. Send the payload. When the program tries to call `exit()`, it will instead call `readflag()` and print the flag.

## Exploit

The exploit script uses pwntools to:
- Load the binary and extract the addresses automatically
- Construct the payload with the GOT address and readflag address
- Send it to the service
- Receive and print the flag

Run it with:
```bash
./exploit <host> <port> [binary_path]
```

If the binary path is not provided, the script will try to find it in common locations.
