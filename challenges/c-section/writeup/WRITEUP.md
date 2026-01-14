## c-section — Writeup

The service exposes a Python “patcher” and a sample program.

The c-infrastructure policy on ELFs is expressed via two sections:

- `.cinfra.file`: a file path on the host
- `.cinfra.contents`: required contents of that file

It only executes the ELF if the host file exists and matches the required contents exactly.

The service also provides a **sample** executable that can read files under `/proc`.

### Key observation

The sample executable itself must pass the same policy, so it contains:

- `.cinfra.file = "/flag"`
- `.cinfra.contents = <the real flag>`

### Exploit

Run the sample (menu option `2`) and ask it to print `/proc/self/exe`. That file is the bytes of the running executable itself, including its section data. Extract `.cinfra.contents` from the dumped ELF to recover the flag.

