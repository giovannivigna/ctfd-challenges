# sox40basic

Exploit a simple **oracle relay**: the service asks you to provide an encryption of a phrase under a fixed (unknown to you) key.
By opening a second connection to the same service, you can ask it to encrypt the phrase for you and relay the ciphertext back.

Make sure that the port in the Dockerfile and in `src/xinetd.conf` are the same.

When testing locally remember to use:
```
% docker build . -t sox40basic
% docker run --publish 11221:11221 sox40basic
```
