# codequill — Writeup

## Goal

Submit a CodeQL query that makes the service print the flag from `/flag`.

## Observations

The target program defines two functions besides `main`:

- `targetFunction(...)`, which is called from `main`.
- `anotherFunction(int)`, which is never called.

So the correct answer is to write a CodeQL query that finds **functions with no call sites**.

## Exploit

Select a function that is **never the target of any `FunctionCall`** (and exclude `main` to avoid returning it as “never called” as well). For example:

```ql
import cpp

from Function f
where
  f.hasDefinition() and
  f.getName() != "main" and
  not exists(FunctionCall fc | fc.getTarget() = f)
select f, f.getName()
```

On the provided program, the only such function is `anotherFunction`, so it appears in the decoded results and the service prints the flag.

## Steps

- Run the service locally: `./scripts/run.sh`
- Execute the exploit: `./writeup/exploit 127.0.0.1 12667`
