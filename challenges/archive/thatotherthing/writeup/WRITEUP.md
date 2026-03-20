# thatotherthing — Writeup

## Overview
The service reads exactly 32 printable ASCII characters and runs them through a validation function.

Players are only given a **compiled binary** (statically linked, with symbols, no source).

## Intended solution (angr)
This challenge is intended to be solved using **symbolic execution** with **angr**.

Key idea: since the binary is statically linked, executing from `main` drags in a lot of libc. Instead, use the symbol table and start directly at `validate(...)`.

The provided solve script:
- Loads the binary with angr
- Locates the `validate` symbol
- Creates a symbolic 32-byte input buffer
- Calls `validate(buf, 32)` via `call_state`
- Constrains the return value to 1 and extracts a satisfying input
- Connects to the remote service and submits the input

Run:

```bash
python3 ./exploit HOST PORT [./thatotherthing]
```
