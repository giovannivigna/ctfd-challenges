#!/bin/bash
IMAGE="oncetimepad"
PORT=7788
docker run --cap-add=SYS_PTRACE -p ${PORT}:${PORT} ${IMAGE}
