#!/bin/bash
IMAGE="aikido"
PORT=6000
docker run -p ${PORT}:${PORT} ${IMAGE}
