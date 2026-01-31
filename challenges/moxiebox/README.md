# moxiebox

This is a reversing challenge that ships a non-native binary (RISC-V 64-bit Linux).

Players should run it with QEMU user-mode:

```bash
qemu-riscv64 ./moxiebox
```

And optionally debug with:

```bash
qemu-riscv64 -g 1234 ./moxiebox
gdb-multiarch ./moxiebox
```
