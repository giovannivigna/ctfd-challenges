# fuzzbiz4

The service asks you for a payload length and then for a payload. It then uses the payload as input for a program that can be made to crash; when it crashes, the service leaks the contents of `/flag`.

## Exploit

- Generate or provide a crashing input for the target binary (see `inputs/` and helper scripts in this directory).
- Send the crashing input as the payload (raw bytes) after first sending its length.

You can use the provided exploit like this:

```bash
python3 exploit.py <host> <port> <file>
./exploit <host> <port> <file>
```

Where `<file>` is a file containing the crashing input.

