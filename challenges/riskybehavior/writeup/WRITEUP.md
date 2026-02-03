# Writeup: riskybehavior

## Overview

You are given a Linux ELF binary for a non-native architecture. The program prints an obfuscated (but reversible) string and asks you to type the deobfuscated version. If you enter the correct string, it prints:

> All right! You guessed that moxie flag!

## Running

Run the binary using QEMU user-mode:

```bash
qemu-riscv64 ./riskybehavior
```

## Why `./riskybehavior` may *not* auto-run (binfmt_misc mismatch)

On many Linux systems, foreign-architecture binaries can be executed transparently via `binfmt_misc` (e.g., `./some-riscv64-elf` automatically invokes `qemu-riscv64-static`).

This challenge intentionally ships an ELF whose header **does not match** typical `binfmt_misc` registrations for RISC-V, so students must learn to invoke QEMU explicitly (and/or understand how binfmt matching works).

- **Check the binfmt registration** on the system:

```bash
cat /proc/sys/fs/binfmt_misc/qemu-riscv64
```

- **What’s going on**: `binfmt_misc` rules specify a `magic` byte string and a `mask`. Only the masked bytes are compared; if they match, the kernel runs the configured `interpreter`.
- In particular, the rule often checks the ELF identification bytes (`e_ident`), including `EI_ABIVERSION` (`e_ident[8]`).
- This binary sets **`EI_ABIVERSION` to a non-zero value**, which prevents the rule from matching, but does **not** prevent manual execution with QEMU.

So if `./riskybehavior` fails with “Exec format error”, that’s expected. Use:

```bash
qemu-riscv64-static ./riskybehavior
```

## Debugging (intended)

Start the program with QEMU’s built-in gdbserver:

```bash
qemu-riscv64 -g 1234 ./riskybehavior
```

In another terminal, attach with GDB:

```bash
gdb-multiarch ./riskybehavior
(gdb) set architecture riscv:rv64
(gdb) target remote :1234
(gdb) continue
```

Set a breakpoint on the function that deobfuscates the string (or on `memcmp`/`strcmp`), step until the deobfuscated flag is present in memory, and read it out.

## Offline solution

The obfuscation operates over the printable ASCII alphabet (95 characters, from space \(0x20\) to tilde \(0x7e\)) with a reversible position-dependent transform. Re-implement the reverse transform and apply it to the obfuscated string the binary prints.
