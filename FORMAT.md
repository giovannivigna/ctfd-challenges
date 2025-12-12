## Instructions to bring a challenge to a standard format.

Challenges are formatted to work on the CTFd platform.

Each challenge must have the following:

* A `flag` directory with a `flag` file. The `flag` file contents are in the form `ictf{SOME_CONTENT}` where `SOME_CONTENT` is replaced with the flag specific to this challenge.
* An `ro` directory which is read-only. If the directory is empty, it must contain a `.gitkeep` file.
* An `rw` directory which is writable. If the directory is empty, it must contain a `.gitkeep` file.
* A `src` directory containing the source code of the challenge as well as configuration files (e.g., `xinetd.conf`)
    - If there is an `xinetd.conf` file the port mentioned should be the one specified in the `CHALLENGE_PORT` variable in `challenge.sh`.
* A `writeup` directory containing:
    - `WRITEUP.md`: a description of the solution 
    - `exploit`: the exploit (usually in Python). If the exploit is in Python, there should also be a `requirements.txt` file with the necessary modules to run the exploit.
    - `HELPER.md`: an agent prompt that can be used to configure an AI-based helper (optional)
* A `challenge.yml` file containing the CTFd specification of the challenge. Note that the flag specified in this file should be the same flag contained in the `flag` file.

If the challenge is a service running in a docker container (which is the most common case), the directory contains also:
* A `scripts` directory, which contains:
    - A `challenge.sh` file, which defines the name of the image (`CHALLENGE_NAME` variable) and the port on which the service operates (`CHALLENGE_PORT` variable). For example, the `babyshot` challenge has the following file:
    ```
    CHALLENGE_NAME="babyshot"
    CHALLENGE_PORT=7631 
    ```
    - A symbolic link to the `build.sh` script contained in the `script` directory in the root of the repo.
    - A symbolic link to the `bundle.sh` script contained in the `script` directory in the root of the repo.
    - A symbolic link to the `run.sh` script contained in the `script` directory in the root of the repo.
    - A symbolic link to the `stop.sh` script contained in the `script` directory in the root of the repo.
* A `Dockerfile` that describes how to build the container. Note that the `EXPOSE` command should match the `CHALLENGE_PORT` specified in the `challenge.sh` file.

Review a single challenge and identify problems and inconsistencies with respect to this description and provide solutions and fixes.