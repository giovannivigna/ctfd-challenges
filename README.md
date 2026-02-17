# CTFd Challenges

These are educational challenges that are formatted to be used with CTFd.
The flag is always in `/flag`.
The challenges in the category 'source code' include a bundle with the whole challenge, which allows one to run the challenge in a docker container.

Each challenge has a `writeup` directory that contains:
* `WRITEUP.md`: a description of the solution 
* `exploit`: the exploit (usually in Python)
* `HELPER.md`: an agent prompt that can be used to configure an AI-based helper (optional)

To build/start/stop a challenge, call the scripts in the `script` directory from the home directory of the challenge.
```
% cd babyshot
% ./scripts/build.sh
% ./scripts/run.sh &
[interact with the challenge]
% ./scripts/stop.sh
```

Please remember to set the `connection` to `null` in the `challenge.yml` file before deployment, otherwise CTFd will use the provided connection string, which will not match with the port assigned to the container.
 
## DONE

* babyshot (command injection)
* sympathy (path injection)

* badcrypt (XOR-encryption with key)
* oncetimepad (time-based seed for encryption)

* whattheenv (environment variables)
* sox40basic (oracle replay)

* sleak (leak memory addresses)
* c-section (section locations in memory)
* esrever (reversing)

* extrafirm (reversing)
* notsofirm (reversing)

* cerebralcortex (QEMU Cortex-M firmware)
* riskybehavior (RISC binary statically linked)
* emulous (PowerPC QEMU user, dynamically linked)

* getbuff (buffer overflow)
* cookiemonster (buffer overflow)
* thisisbss (BSS overflow)
* formath (format string)
* longshotr (integer overflow)
* badtable (index manipulation)

* loggable
* loggable2
* nocat-noflag
* secretword
* secretword2


## TODO

* fiddle (started, partial)
* filesync (partial)

* assemblex (assembly)
* codequill (codeQL)

## Web
* admitone
* blinddate
* bombshell
* doomtemple
* webifile
* webinject


## AI
* aikidobot

## NETWORK
* arpattack

## FUZZING
* fuzzbiz
* reflector

* tcpspoof

# Prompt for Co-pilots

Look at the CTFd challenge in the <challenge> directory. 
Read the requirements specified in the file FORMAT.md and tell me how you would modify the challenge to make it conformant to the required format. 
Make sure that the exploit works.
Do not modify any file outside the challenge directory.