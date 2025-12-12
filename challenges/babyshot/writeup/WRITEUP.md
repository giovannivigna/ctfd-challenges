# Sample Remote Challenge Walkthrough

In order to solve the challenge, it is necessary to connect to the server and perform a command injection.
In the line:
```
snprintf(command, sizeof(command), "ps aux | grep ^%s", username);
```
the `username` is provided by the user and it is not sanitized.
By adding special shell characters to the `username`, it is possible to execute arbitrary commands. 
Specifically, passing the value `foo; cat /flag` as the username, it is possible to access the flag contents.
