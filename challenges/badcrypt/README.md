# Badcrypt

A bad encryption algorithm is used to encrypt a gzipped file.
Analyze the file and extract the flag.

The algorithm protects the data using the following transformation:
encrypted[i] = rotater(orig[i], n) ^ key[i mod len(key)],
where each byte of the clear-text file is shift-rotated right n times and then XOR-ed with one of the bytes of the key.
The algorithm takes an arbitrarily long key, but the key must always be shorter than the name of the file to encrypt.
Before encryption, the file is conveniently compressed with gzip, to reduce cloud storage costs.