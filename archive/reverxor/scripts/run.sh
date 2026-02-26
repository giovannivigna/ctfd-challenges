#!/bin/bash
IMAGE="reverxor"
PORT=22211
docker run -p ${PORT}:${PORT} ${IMAGE}
