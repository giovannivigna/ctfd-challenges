# nocat-noflag Write-up

The service accepts a command and executes it via a shell, but with simple substring filtering that blocks the direct use of `cat` and the full flag path.

To bypass the filter:

- Build the forbidden tokens dynamically from smaller strings (e.g. split `cat` into `c` + `at`, and `/flag` into `/fl` + `ag`).
- Expand the variables in the shell so the final command becomes `cat /flag` without those substrings appearing verbatim in the input.

This prints the contents of `/flag`, revealing the flag.

