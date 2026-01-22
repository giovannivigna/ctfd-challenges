# Onekick

The challenge provides a binary that reads 16 bytes from stdin:
- First 8 bytes are treated as an address
- Second 8 bytes are written to that address
- Then the program returns from `main()`

The binary is compiled with:
- `-no-pie`: No Position Independent Executable (addresses are fixed)
- `-z norelro`: No Relocation Read-Only (.fini_array is writable)
- `-fstack-protector-strong`: Stack canary protection (prevents overwriting return address on stack)

There is a function `readflag()` that reads and prints `/flag`, and a destructor function that will be called when the program exits.

## Solution

The `.fini_array` section (which contains destructor function pointers) is writable since RELRO is disabled. Note that stack canary protection is enabled, so overwriting the return address on the stack will trigger a stack smashing detection and abort the program. Therefore, you must use `.fini_array` instead.

When a program exits (by returning from `main()`), functions registered in `.fini_array` are called. We can overwrite a pointer in `.fini_array` to point to `readflag()` instead.

1. Find the address of `.fini_array`:
   ```bash
   readelf -S onekick | grep fini_array
   ```
   Or using objdump:
   ```bash
   objdump -h onekick | grep fini_array
   ```

2. Find the address of `readflag()`:
   ```bash
   objdump -t onekick | grep readflag
   ```
   Or using nm:
   ```bash
   nm onekick | grep readflag
   ```

3. Construct the payload:
   - First 8 bytes: address of `.fini_array` (or the first entry in it)
   - Second 8 bytes: address of `readflag()`

4. Send the payload. When the program returns from `main()`, it will call the destructor function pointer, which now points to `readflag()`, printing the flag.

## Exploit

The exploit script uses pwntools to:
- Load the binary and extract the `.fini_array` section address
- Extract the `readflag()` function address
- Construct the payload with the `.fini_array` address and readflag address
- Send it to the service
- Receive and print the flag

Run it with:
```bash
./exploit <host> <port> [binary_path]
```

If the binary path is not provided, the script will try to find it in common locations.

## Note on .fini_array

The `.fini_array` section contains function pointers to destructor functions that are called when the program exits (by returning from `main()`). With RELRO disabled (`-z norelro`), this section is writable, allowing us to overwrite the destructor pointer to redirect execution to `readflag()`.
