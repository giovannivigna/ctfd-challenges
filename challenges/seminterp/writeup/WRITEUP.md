## Summary

The service prints a Python file (`vuln_app.py`) that contains three vulnerabilities. You must submit a Semgrep YAML configuration with three rules (specific IDs) that match the vulnerable lines.

## Required rule IDs

Your config must contain rules with these IDs:

- `seminterp.sqli`
- `seminterp.cmdi`
- `seminterp.pickle`

The service runs Semgrep on `vuln_app.py` and checks that each rule produces a finding on the intended vulnerable line.

## One working solution

Save the following as a Semgrep config and submit it to the service:

```yaml
rules:
  - id: seminterp.sqli
    languages: [python]
    message: "Potential SQL injection via string formatting"
    severity: ERROR
    pattern: query = "SELECT email FROM users WHERE username = '%s'" % username

  - id: seminterp.cmdi
    languages: [python]
    message: "Command injection via shell=True"
    severity: ERROR
    pattern: subprocess.check_output(..., shell=True)

  - id: seminterp.pickle
    languages: [python]
    message: "Insecure deserialization"
    severity: ERROR
    pattern: pickle.loads(...)
```

## Getting the flag

When all three rules match, the service prints the flag.
