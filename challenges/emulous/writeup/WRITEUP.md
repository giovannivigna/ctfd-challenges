# emulous — writeup

## Overview

The downloadable file is a **PowerPC Linux ELF** that:

- Prompts for a password
- Complains if the password does not exist in `/usr/share/dict/words`
- Uses the password as an **AES key** to decrypt an embedded ciphertext
- If the decrypted result is printable ASCII, it prints it; otherwise prints `Sorry no printable output!`

It is also intentionally shipped with a patched ELF `e_ident` so that common
`binfmt_misc` QEMU registrations do not auto-trigger; you must invoke QEMU.

## Running

Because the binary is **dynamically linked**, QEMU user-mode needs a PowerPC
sysroot to find the loader and libraries:

```bash
qemu-ppc -L /path/to/ppc/sysroot ./emulous
```

## Solving

The ciphertext is **AES-128-CBC** with **PKCS#7 padding**.

- **Key derivation**: the password bytes, NUL-padded (or truncated) to 16 bytes
- **IV**: constant (`emulous_iv__2026`)

To solve, brute-force a wordlist (dictionary) as candidate passwords:

- decrypt the embedded ciphertext with each candidate password-derived key
- accept only if PKCS#7 padding is valid and the plaintext is printable ASCII

The correct decryption yields the flag.

