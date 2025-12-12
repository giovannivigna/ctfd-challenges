#!/bin/bash
IMAGE="codequill"
PORT=12667
docker run -p ${PORT}:${PORT} ${IMAGE}
