## secretword2 — Writeup

### Summary
The service asks for a “secret” string. Internally, it decrypts a fixed ciphertext using an RC4-like stream cipher with a hardcoded key, then compares your input against the decrypted secret. If you send the correct secret, it prints the contents of `/flag`.

### What to reverse
- The binary contains:
  - A hardcoded **key**: `SuperSecretKey`
  - A hardcoded **ciphertext** (byte string)
  - An RC4-style KSA/PRGA routine used to XOR-decrypt the ciphertext into the real secret

Once you recover the key and ciphertext (e.g., by static analysis or debugging), you can reimplement the decryption locally and send the resulting plaintext to the service.

### Exploit
The provided exploit script (`writeup/exploit`) implements the same RC4-like decryption using the constants extracted from the binary, connects to the service, waits for the prompt, and sends the decrypted secret to obtain the flag.

Run:
```bash
./exploit HOST PORT
```

