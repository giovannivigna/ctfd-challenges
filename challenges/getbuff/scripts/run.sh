#!/bin/bash
IMAGE="getbuff"
PORT=28651
docker run --cap-add=SYS_PTRACE -p ${PORT}:${PORT} ${IMAGE}
