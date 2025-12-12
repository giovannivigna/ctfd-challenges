#!/bin/bash
IMAGE="thisisbss"
PORT=1105
docker run -p ${PORT}:${PORT} ${IMAGE}
