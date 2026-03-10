# Popenepop Challenge Walkthrough

## Overview

The challenge presents a menu-driven service with several options. The goal is to read the contents of `/flag`.

## Menu Options

1. **Get user info** – Runs `getent passwd <username>` via `popen()` with user-supplied input
2. **List all users** – Runs `getent passwd` (no user input)
3. **Create file (under /tmp)** – Writes content to a path under `/tmp`
4. **Read file (under /tmp)** – Reads and prints a file under `/tmp`
5. **Exit**

## Vulnerability Analysis

### Sink

The command injection sink is in option 1:

```c
snprintf(cmd, 512, "getent passwd %s", user);
// ...
FILE *fp = popen(command, "r");
```

The `user` value is interpolated into a shell command executed by `popen()`.

### Source

The username is read from stdin in the "Get user info" flow and passed through `normalize()` before being used in `build_command()`.

### Sanitization

The `normalize()` function rejects the input entirely if it contains any disallowed character. Only these characters are allowed:

- Alphanumeric: `a-z`, `A-Z`, `0-9`
- Special: `$`, `(`, `)`, `{`, `}`, `/`, `>`, `<`

Blocked characters include: spaces, `;`, `|`, `&`, `` ` ``, `\`, newlines, etc. This prevents trivial injection like `foo; cat /flag`.

### Blind Corner

The allowed characters still permit:

- **`$()`** – Command substitution
- **`<`** – Input redirection
- **`>`** – Output redirection
- **`/`** – Path separators

## Exploit Strategy

We cannot use spaces, so we need to chain commands without them. Key tricks:

1. **`$(...)`** – Execute a command and substitute its output
2. **`cat</flag`** – Read `/flag` via stdin redirection (no space needed)
3. **`>/tmp/x`** – Redirect stdout to a file under `/tmp`

By combining these: `$(cat</flag>/tmp/x)`:

- `cat</flag` reads `/flag` and writes to stdout
- `>/tmp/x` redirects that stdout to `/tmp/x`
- The command substitution returns empty (stdout was redirected)
- The flag is now in `/tmp/x`, which we can read via option 4

## Solution Steps

1. **Option 1** – Get user info, enter username: `$(cat</flag>/tmp/x)`
2. **Option 4** – Read file, enter path: `/tmp/x`
3. The flag is printed.

## Automated Exploit

See `exploit` for a pwntools script that automates this.
