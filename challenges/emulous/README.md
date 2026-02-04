# emulous

This is a reversing challenge that ships a **PowerPC Linux ELF**.

The binary is **dynamically linked** on purpose, so when running it under QEMU
user-mode you will need to provide a matching PowerPC sysroot (loader + libc).

Run it with QEMU user-mode (example):

```bash
qemu-ppc -L /path/to/powerpc/sysroot ./emulous
```

This challenge also uses the same `binfmt_misc` mismatch trick as `riskybehavior`
to prevent `./emulous` from being transparently executed via a system-wide QEMU
binfmt registration. Invoke QEMU explicitly.

## Intended solve

Brute-force a wordlist (dictionary) as the password until the program prints a
printable ASCII output (the flag).

