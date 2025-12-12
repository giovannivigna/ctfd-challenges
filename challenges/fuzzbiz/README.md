# whattheenv

Exploitation involving environment variables.

Make sure that the port in the Dockerfile and in src/xinetd.conf are the same.

When testing locally remember to use 
```
% docker build . -t whattheenv
% docker run --publish 11239:11239 whattheenv
```
