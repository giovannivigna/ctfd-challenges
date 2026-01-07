# sox40basic — Writeup

The service uses a fixed secret key (unknown to the player) to encrypt/decrypt strings using Fernet.

## Service flow

1. You provide any plaintext.
2. The service returns a base64-encoded ciphertext for it.
3. The service generates a random *challenge phrase* and asks you to send back the encrypted version of that phrase.
4. If decryption matches the phrase, it prints the flag.

## Key observation (oracle relay)

Even though you do not know the key, **the service itself can encrypt arbitrary plaintext for you** (step 1→2).

So:

- Connection A gives you the challenge phrase.
- Connection B is used as an “encryption oracle”: you send the challenge phrase as your chosen plaintext, and it returns the ciphertext.
- You relay that ciphertext back to connection A to pass the verification check and get the flag.

## Exploit

Run the provided exploit script:

```bash
./exploit HOST PORT
```

It opens two connections and relays the challenge phrase automatically.


