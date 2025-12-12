#!/bin/bash
IMAGE="whattheenv"
PORT=11239
docker run -p ${PORT}:${PORT} ${IMAGE}
