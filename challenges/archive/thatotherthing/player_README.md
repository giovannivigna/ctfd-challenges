# thatotherthing (player files)

You are given a single Linux `x86_64` ELF binary: `thatotherthing`.

- It is **statically linked**.
- It includes **symbols** (so `nm`/`objdump` will show function names).
- It has **no source** and is intended to be solved via **symbolic execution**.

## Running

```bash
chmod +x ./thatotherthing
./thatotherthing
```

It will ask for exactly **32** printable ASCII characters.

## Hint

The interesting function is named `validate`. A common angr approach is to start symbolic execution at `validate(...)` (instead of `main`) to avoid spending time in libc.
