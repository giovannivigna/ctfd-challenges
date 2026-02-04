## formath — writeup

### Vulnerability
The service builds a message using `snprintf()` and then prints it with `printf(msg)`.
Because the message contains attacker-controlled strings (the chosen function name and parameter),
this becomes a **format string vulnerability**.

### Exploitation idea
- Leak a stack pointer from the banner (`Execution id: %p`).
- Use a format string payload to overwrite the saved return address with the address of shellcode
  placed on the stack (sent as part of the “function name” input).
- When execution returns, it jumps to the shellcode and we can read the flag from `/flag`.

### Reproducing
- **Local**:
  - Run the container with `./scripts/run.sh`
  - Run the exploit: `./writeup/exploit --local`
- **Remote**:
  - `./writeup/exploit --remote <host> <port>`

