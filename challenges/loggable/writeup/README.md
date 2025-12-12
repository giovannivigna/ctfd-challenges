# Loggable Remote Challenge Walkthrough
In order to solve the challenge, it is necessary to connect to the server and perform a command injection.
Some of the injection characters are sanitized, but 'backtick' can still be used.
By passing the value ``foo" `cat /flag.txt` "bar`` it is possible to access the flag contents.
