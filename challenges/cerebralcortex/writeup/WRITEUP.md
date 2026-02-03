# cerebralcortex — Writeup

## Goal

Recover the flag embedded (obfuscated) in the Cortex-M firmware image.

The firmware:

- deobfuscates an internal string (the flag)
- reads `/flag` from an embedded filesystem inside the firmware image
- compares the checksum of `/flag` with the checksum of the deobfuscated string
- prints `Correct checksum in /flag file!` and exits when they match

## Solution sketch

1. Load the ELF into a disassembler (Ghidra/IDA) or debug it with QEMU + `gdb-multiarch`.
2. Find the deobfuscation routine and the obfuscated byte array in `.rodata`.
3. Reimplement the deobfuscation (a simple XOR stream) to recover the plaintext string
4. Locate the embedded filesystem blob (a tiny `cpio` “newc” archive) and patch the `/flag` file
   contents inside it to match the recovered flag, then re-run the firmware.

## Run with QEMU

From the challenge directory:

```bash
qemu-system-arm -M lm3s6965evb -nographic \
  -kernel src/cerebralcortex.elf \
  -semihosting-config enable=on,target=native
```

Expected output (before patching the embedded filesystem):

- `Wrong checksum in /flag file!`

## Debug with QEMU + pwndbg

### Start QEMU and wait for GDB

```bash
qemu-system-arm -M lm3s6965evb -nographic \
  -kernel src/cerebralcortex.elf \
  -semihosting-config enable=on,target=native \
  -S -gdb tcp::1234
```

### Attach with GDB (pwndbg)

Open another terminal, start `gdb-multiarch` on the ELF (pwndbg should auto-load if installed):

```bash
gdb-multiarch -q src/cerebralcortex.elf
```

Inside GDB:

```gdb
target remote :1234

# optional, but usually helpful on bare metal
set confirm off
set pagination off

# break at the entrypoint and run
break main
continue
```

Common next steps:

```gdb
info registers
x/16i $pc
bt
```

If you’re using pwndbg, you can use its helpers (e.g. `context`, `telescope`, `hexdump`) to inspect
buffers while stepping through the deobfuscation routine and the embedded filesystem parser.

