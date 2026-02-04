# Badtable exploitation

## Setup notes

The goal is to make the service print the contents of the flag file (`/flag`).

## Analysis

The service stores integers in a fixed-size stack array:

- `int array[1024];`

but the `Index` is never bounds-checked for either read or write, so you can read/write out-of-bounds and reach saved registers on the stack.

## Exploitation outline

1. Leak a stack pointer with an out-of-bounds read (e.g. `array[1030]`).
2. Use the leaked pointer to compute the address of `array`.
3. Write shellcode into the beginning of `array`.
4. Overwrite the saved return address to jump to your shellcode.
5. Shellcode reads `/flag` and exits.

The provided `exploit` script implements this.

