# Fiddle — Writeup

The service stores a `/flag` file descriptor and an array of other file descriptors inside a single `struct`.

It asks for:
- a message
- a number `k`
- `k` integers (FD array indices)

The first `k-1` indices are used to route the message through a sequence of file descriptors (alternating write/read stages).

Finally, the service prints the “result” by doing:

```c
int out_fd = st.fds[out_idx];  // out-of-bounds if out_idx < 0
print_fd_contents(out_fd);
```

There is **no bounds check** on the final `out_idx`.

Because `flag_fd` is stored immediately before `fds[]` in the struct, using `out_idx = -1` makes `st.fds[-1]` refer to `st.flag_fd`, leaking the **unencrypted flag**.

## Exploit

Send any valid message, set `k >= 2`, pick any valid index for the first stage (a `memfd` or `shm` index works), and set the last index to `-1`.

