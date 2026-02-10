# secretword — Writeup

## Overview
You are given the compiled binary (`src/secretword`, built with debugging symbols). Each time the service runs it generates a **new random secret**
made of several English words. The service then XOR-encrypts it with a repeating key and prints the **encrypted**
secret as a hex string.

To get the flag you must decrypt the printed ciphertext and send back the plaintext secret.

## Key observation
In the binary the encryption is a simple repeating-key XOR:

- `KEY`: `"SuperSecretKey"` (embedded in the binary; you can recover it via a debugger or by inspecting strings/data)
- encrypt/decrypt: `buf[i] ^ KEY[i % KEY_LEN]`

Repeating-key XOR is symmetric, so decrypting is the same operation as encrypting.

## Exploitation
1. Connect to the service and read the line `Encrypted secret (hex): ...`.
2. Hex-decode it to bytes.
3. XOR-decrypt with the repeating key `"SuperSecretKey"` to recover the plaintext secret (ASCII words).
4. Send the plaintext back at `Enter the secret:`.
5. The service prints the flag.

Example decrypt snippet (standalone):

```python
import binascii

key = b"SuperSecretKey"
secret_hex = "..."  # string printed by the service
ciphertext = binascii.unhexlify(secret_hex)
plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))
print(plaintext.decode())
```

## Exploit
Run:

```bash
./exploit HOST PORT
```

