# codequill — Writeup

## Goal

Submit a CodeQL query that makes the service print the flag from `/flag`.

## Observations

The service:

- Prints the provided C program.
- Accepts a CodeQL query terminated by a line containing `DONE`.
- Runs the query and decodes results to CSV.
- Checks the CSV output with a very small validator:
  - If the output contains `targetFunction`, it fails.
  - If the output contains `anotherFunction`, it succeeds.
  - It also checks that the query text contains `from`, `where`, and `select`.

Crucially, it **does not actually verify** that the returned function is “never called”; it only checks for the presence of the string `anotherFunction` in the decoded output.

## Exploit

Return `anotherFunction` directly by selecting the function by name. For example:

```ql
import cpp

from Function f
where f.getName() = "anotherFunction"
select f, f.getName()
```

This makes the decoded CSV include `anotherFunction`, passes the validator, and the service prints the flag.

## Steps

- Run the service locally: `./scripts/run.sh`
- Execute the exploit: `./writeup/exploit 127.0.0.1 12667`
