# whattheenv

Exploitation a simple command injection.

Make sure that the port in the Dockerfile and in src/xinetd.conf are the same.

When testing locally remember to use 
```
% docker build . -t whattheenv
% docker run --publish 11239:11239 whattheenv
```
