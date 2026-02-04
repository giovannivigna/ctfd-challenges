## longshotr — writeup

### Vulnerability
The program prints user input directly as a format string:

- `verify_username()` lowercases the provided name and then calls `printf(username)`.

This is a classic **format string vulnerability** which can be used to leak memory and write to arbitrary addresses.

### Exploitation idea
- Use the format string to obtain the correct stack offset and leak an address to compute the libc base.
- Overwrite a GOT entry (e.g. `strlen`) with `system`.
- Trigger the call with a crafted “filename” such as `/bin/sh;__` to obtain code execution and read `/flag.txt`.

### Reproducing
- **Local**:
  - Build/run the container: `./scripts/build.sh` then `./scripts/run.sh`
  - Run exploit: `./writeup/exploit --local` (or adjust the script if needed)
- **Remote**:
  - `./writeup/exploit <host> <port>`

