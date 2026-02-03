# cerebralcortex

This is a reversing challenge that ships a **bare-metal Cortex-M** firmware image.

When the firmware starts, it deobfuscates an internal string (the flag) and then reads `/flag`
from an **embedded filesystem inside the firmware image**.

The embedded `/flag` content is intentionally wrong by default (e.g. `FAKEDATANOTWORKING`), so
students must patch the firmware image (or the embedded filesystem blob) after analysis.

If `/flag` has the right checksum, the firmware prints:

> `Correct checksum in /flag file!`

and terminates.

## Run locally (QEMU full-system)

This firmware uses **ARM semihosting** for stdout/exit. `/flag` is read from the embedded filesystem.

From this directory, you can use the provided runner:

```bash
./run.sh
```

Or run QEMU directly:

```bash
qemu-system-arm -M lm3s6965evb -nographic \
  -kernel src/cerebralcortex.elf \
  -semihosting-config enable=on,target=native
```

