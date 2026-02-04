# thisisbss

## Summary

The service reads a filename into a fixed-size global buffer and then:

1. `stat()`s the provided path
2. checks the file is owned by the running user
3. executes `/bin/cat <filename>` via `system()` (without quoting)

The intended solution is to leverage the unsafe handling of the filename to bypass the ownership check and read the flag from `/flag`.

