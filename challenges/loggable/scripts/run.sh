#!/bin/bash
IMAGE="loggable"
PORT=4242
docker run -p ${PORT}:${PORT} ${IMAGE}
