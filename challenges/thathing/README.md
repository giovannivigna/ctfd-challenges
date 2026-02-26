# thathing

A KLEE-friendly symbolic execution challenge.

The service reads a single line, runs it through a deliberately annoying validation function, and prints /flag if the input is correct.

The intended approach is to compile the validation code to LLVM bitcode and solve it with the KLEE symbolic execution engine.
