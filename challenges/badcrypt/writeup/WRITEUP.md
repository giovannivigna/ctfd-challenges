# Badcrypt Walkthrough

Gzip adds the filename to the beginning of the file. 
Since the key is XOR-ed, it is possible to obtain the key, modulo a shift (which is unknown).
By brute-forcing 8 possible shifts, one can obtain the key.
It's a known plaintext attack.