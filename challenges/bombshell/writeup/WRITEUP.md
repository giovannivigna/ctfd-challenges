# bombshell

## Summary

The app provides an authenticated “system scan” feature that runs `ping` on a user-supplied target. The target is interpolated into a shell command and executed with `shell=True`, which allows command injection.

## Vulnerability

In `src/app/app.py`, the scan endpoint builds a command string:

- `cmd = f"ping -c 1 {target}"`
- `subprocess.check_output(cmd, shell=True, ...)`

Because `target` is not sanitized, an attacker can append `; <command>` and execute arbitrary commands in the container.

## Exploitation

1. Register a new user and login.
2. Submit a scan with an injected target such as:

`127.0.0.1; cat /flag`

3. The response contains the flag.

## One-shot exploit

Run the provided exploit script:

```bash
./writeup/exploit http://127.0.0.1:12721
```

