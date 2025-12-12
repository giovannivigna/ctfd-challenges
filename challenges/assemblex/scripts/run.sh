#!/bin/bash
IMAGE="assemblex"
PORT=36363
docker run -p ${PORT}:${PORT} ${IMAGE}
