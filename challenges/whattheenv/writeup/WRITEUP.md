# whattheenv Write-up

This challenge is a somewhat complicated service that requires several interactions for exploitation.
The service allows one to load a variable name and its value.
This value is entered in the environment using `setenv()`.

The service also allows one to store the value of an existing variable.
The user provides the name of the variable and the service stores the variable with the permissions stored in the file `~/permissions`, which by default contains the string `0666`.

When the user quits, the command `ls` is executed using `execlp()` to show the currently stored values.

The goal is to created an executable file with name `ls` and the contents `#!/bin/cat /flag` and to convince the program to execute that file.

The `execlp()` function uses the `PATH` variable to find the executable and so this must be set using a `load` command.
Before that it is necessary to convince the application to create stored variable with permissions `0777`.
To do this, one has to first create an environment variable called `permissions` with the `0777` content and request that it is stored in the file system.
Since the variable is referenced using `~` one has to overwrite `HOME` with the current directory. 
From that point on, all the variables will be stored in an executable file and creating the `ls` file will be straightforward.  


