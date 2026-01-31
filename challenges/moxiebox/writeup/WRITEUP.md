# Writeup: moxiebox

## Overview

You are given a Linux ELF binary for a non-native architecture. The program prints an obfuscated (but reversible) string and asks you to type the deobfuscated version. If you enter the correct string, it prints:

> All right! You guessed that moxie flag!

## Running

Run the binary using QEMU user-mode:

```bash
qemu-riscv64 ./moxiebox
```

## Debugging (intended)

Start the program with QEMU’s built-in gdbserver:

```bash
qemu-riscv64 -g 1234 ./moxiebox
```

In another terminal, attach with GDB:

```bash
gdb-multiarch ./moxiebox
(gdb) set architecture riscv:rv64
(gdb) target remote :1234
(gdb) continue
```

Set a breakpoint on the function that deobfuscates the string (or on `memcmp`/`strcmp`), step until the deobfuscated flag is present in memory, and read it out.

## Offline solution

The obfuscation operates over the printable ASCII alphabet (95 characters, from space \(0x20\) to tilde \(0x7e\)) with a reversible position-dependent transform. Re-implement the reverse transform and apply it to the obfuscated string the binary prints.
