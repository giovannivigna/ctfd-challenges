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

## DONE
* babyshot
* badcrypt
* whattheenv
* sympathy
* sox40basic
* oncetimepad
* sleak

## TODO

* aikidobot
* arpattack
* assemblex
* badtable
* blinddate
* cookiemonster
* formath
* fuzzbiz
* getbuff
* loggable
* loggable2
* longshotr
* nocat-noflag
* reflector
* secretword
* secretword2
* shortname
* tcpspoof
* thisisbss
* webifile
* webinject

# Prompt for Co-pilots

Look at the CTFd challenge in the <challenge> directory. 
Read the requirements specified in the file FORMAT.md and tell me how you would modify the challenge to make it conformant to the required format. 
Do not modify any file outside the challenge directory.

Look at the CTFd challenge in the loggable directory. 
Read the requirements specified in the file FORMAT.md and tell me how you would modify the challenge to make it conformant to the required format. 
Do not modify any file outside the challenge directory.