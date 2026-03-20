# cookiemonster

This challenge spawns a simple service on port 5004.

You can connect to it with:

`nc 127.0.0.1 5004`

The vulnerable program is built from `src/cookiemonster.c` and exposed as a TCP service via `xinetd`.
