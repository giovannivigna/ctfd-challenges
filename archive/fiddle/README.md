# Fiddle

Fiddle is a challenge that shows all the way in which data can be passed back and forth between a parent process and a child process.

The service (fiddle.c) when started creates a series of file descriptors using the following functions:
- shm_open/ftruncate/mmap: The child process will open the same shared file and use it to exchange a message with the server 
- socketpair:  The child process will inherit the file descriptors and use them to communicate with the parent
- pipes: The child process will inherit the file descriptor
- memfd_create: The child process inherits the open file descriptor

The server creates a random number of these descriptors (less than 50) with various types.
Each descriptor is stored in an integer array.
Each creation of a file descriptors is associated with the printing of a message that states the type of descriptor and the array index where it is stored.

This file descriptors are stored in a data structure that has:
- the file descriptor of the /flag file
- the array of integers with all the other file descriptors

The server then requests from the user a text message and series of integers.
The integers represents indexes in the array of integers that need to be consecutively written to and read from.
If the message is read correctly from beginning to end, the system returns the content of the flag, encrypted with a secret random key that changes at every execution.

The exploit is that by using -1 as the last series of file descriptor indexes, the system reveals the actual unencrypted flag.