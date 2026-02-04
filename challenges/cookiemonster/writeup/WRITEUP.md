# cookiemonster

## Bug

The program has a stack buffer overflow:

- It declares `char buf[8];`
- Later it reads a name with `fgets(buf, 0x40, stdin);`

This allows overwriting the saved return address.

## Exploit idea

The binary is compiled without PIE, so the address of `give_shell()` is fixed. We overwrite the return address with `give_shell()` to get a shell, then read `/flag`.

## Steps

1. Send `-1` to exit the "inspect" loop.
2. Send a name payload: `A * 16 + p64(give_shell)`.
3. In the resulting shell: `cat /flag`.

## Exploit

See `writeup/exploit`.

