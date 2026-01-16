# esrever — Writeup

This service sends you a freshly compiled ELF binary and asks four questions about it:

1. The **virtual address** of the executable **text** load segment.
2. The **total size** of all **writable** `SHT_PROGBITS` sections (initialized data), in **decimal**.
3. A **secret password** embedded in the binary.
4. The **virtual address** of the `main` function.

The server-side logic that validates answers is in `src/esrever.py`, so the most reliable solve strategy is to replicate its extraction logic.

## Solution outline

- Connect and parse the first line: `Binary length: N`
- Read exactly `N` bytes from the socket and save them to a local file (an ELF executable).
- Use `pyelftools` to parse the ELF:
  - **Text segment address**: first `PT_LOAD` segment with the executable flag set (`p_flags & 0x1`), answer is `p_vaddr`.
  - **Initialized data size**: sum `sh_size` for every section where:
    - `sh_type == SHT_PROGBITS`
    - `sh_flags` includes writable (`sh_flags & 0x2`)
  - **main address**: locate the `main` symbol in any symbol table and return `st_value`.
  - **secret password**:
    - Prefer reading the `secret` symbol (if present) by translating its virtual address to a file offset via the `PT_LOAD` segments and reading a null-terminated ASCII string.
    - Fallback: scan writable `SHT_PROGBITS` data for a null-terminated 16-character alphanumeric string.
- Send the four answers back to the service and receive the flag.

## Reference solver

See `writeup/exploit` (Python). It implements the steps above and prints the recovered `ictf{...}` flag when successful.

