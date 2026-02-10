# Loggable Remote Challenge Walkthrough
In order to solve the challenge, it is necessary to connect to the server and perform a command injection.
The service uses a regular expression that accepts legal input.
The author of the regex used the character '-' to specify that the character should be allowed.  
However, the character instead specified a range of characters, which happens to include ';'

By passing the value ``foo"; cat /flag; echo "bar`` it is possible to access the flag contents.
