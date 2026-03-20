# thathing — Writeup

## Overview
The service reads exactly 24 printable ASCII characters and runs them through a validation function designed to be annoying to solve manually (byte rotations, mixed arithmetic, stateful checks).

If the input is correct, the program prints the contents of `/flag`.

## Intended solution (KLEE)
This challenge is intended to be solved with **symbolic execution** using **KLEE**.

Important detail: the KLEE harness (`writeup/klee_harness.c`) is kept in the writeup material and is **not shipped to players** via the bundle.

### Using the KLEE Docker image
From the challenge `src` directory, you can compile to LLVM bitcode, link with the harness, and run KLEE inside the `klee/klee` container.

Example (paths will vary):

~~~bash
# from challenges/thathing/src

# compile + link + run KLEE (in container)
docker run --rm   -v "${PWD}/..":/work   -w /work/src   klee/klee   bash -lc 'set -euo pipefail;     clang -emit-llvm -c -DTHATHING_NO_MAIN thathing.c -o thathing.bc;     clang -emit-llvm -c ../writeup/klee_harness.c -o harness.bc;     llvm-link thathing.bc harness.bc -o linked.bc;     klee -max-time=300s linked.bc'

# extract a concrete input from the generated test case
docker run --rm   -v "${PWD}/..":/work   -w /work/src   klee/klee   bash -lc 'f=; ktest-tool .ktest$(ls -1 klee-last/*.ktest | head -n 1)'
~~~

KLEE will produce a test case that satisfies `validate(...)`, which corresponds to the correct 24-character input.

## Exploit
The provided exploit script demonstrates the intended approach end-to-end:
- Runs KLEE in the `klee/klee` Docker container
- Extracts the 24-byte solution from the generated `.ktest`
- Connects to the service and sends the derived input

Run:

~~~bash
./exploit HOST PORT
~~~
