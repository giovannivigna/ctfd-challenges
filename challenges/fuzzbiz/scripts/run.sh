#!/bin/bash
IMAGE="fuzzbiz"
PORT=7766
docker run -p ${PORT}:${PORT} ${IMAGE}
