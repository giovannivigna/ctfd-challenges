#!/bin/bash
IMAGE="webifile"
PORT=8862
docker run -p ${PORT}:${PORT} ${IMAGE}
