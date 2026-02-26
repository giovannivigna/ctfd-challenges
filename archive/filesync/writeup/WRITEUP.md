The challenge has a server component that provide the user with three options: 
1) invoke the writer
2) invoke the reader
3) reset

The server creates a file "shared.txt" in a unique temporary directory that the reader and writer sync on.
The server writes the sentence "Hello, hackers!" at the beginning of the file.
Invoking the writer allows one to specify a file and the content of the file is written to the shared file.
The writer can only be invoked if the reader has been invoked first.
The reader opens the file "shared.txt" (using fopen) and reads its contents and then every second checks for new content.
However, the reader never clears the EOF error and therefore additional file writing is not perceived by the reader who always thinks its an EOF.

The reset  functionality is hidden by a password that is the rot13 version of "hackers".
If the password is provided the service sends a SIG_USR1 signal to the reader who performs a clearerr() on all the file descriptors.   