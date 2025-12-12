# Get buff
In order to solve the challenge, it is necessary to overflow the buffer buf and cat the flag.

The binary is running in a container, which runs `xinetd`.
When a connection is made, `xinetd` runs the `service.sh` script, which, in turn, runs `getbuff`.
This makes debugging a bit difficult.
In addition, the binary has a timeout of 10 seconds.
IMPORTANT: You need to start the container with:
``docker run --cap-add=SYS_PTRACE -p 28651:28651 getbuff-image``
otherwise, you will not be able to attach gdb.
Also, you need to make sure that the kernel variable `ptrace_scope` is set to 0, by executing the following line on the host (not the container):
``echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope``

The first problem to solve is to remove the timeout.
First you need to copy the binary out of the container.

Get the container id:
``docker container list``

Copy the file out:
``docker cp <container id>:/home/challenge/ro/getbuff .``

Now open the file in Ghidra and identify the timeout variable, by looking at the source code and clicking on the variable, which will bring you to the location on the BSS where the variable is.

To modify the value you need to open the Window->Binary view and then click on the pen (edit mode).
Change the value and export the file to "Raw bytes".

Copy the file back
``docker cp getbuff-notimeout <container id>:/home/challenge/ro/``

Get a shell on the container:
``docker exec -it <container id> /bin/bash``

Now mv `getbuff` to `getbuff.orig` and copy `getbuff-notimeout` to `getbuff`.
Now connect to the service to verify that the timeout does not exist.

Your exploit will:
- connect and receive the address of the buffer
- create the shellcode
- wait for your input before sending the shellcode

When the process is waiting, find the PID of the `getbuff` process in the container:
``# ps aux | grep getbuff``

Attach gdb to the `getbuff` process:
``# gdb -p <pid>``

See the listing by using the list command:
``(gdb) list``
and find the line right after the buffer was read (e.g., line 78).
Put a break there and then continue the execution:
```
(gdb) b 78
(gdb) c
```
At this point, continue the execution of the exploit by sending the actuall shellcode.
After that the debugger will break and you can analyze the surroundings of `$ebp` to see if the modifications were correct (usually it's a matter of adjusting the number of NOPs to achieve the correct alignment)

```
(gdb) x $ebp
(gdb) x $ebp + 4 // EIP!
...

```

