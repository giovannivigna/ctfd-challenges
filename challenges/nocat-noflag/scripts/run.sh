#!/bin/bash
IMAGE="nocat-noflag"
PORT=25252
docker run -p ${PORT}:${PORT} ${IMAGE}
