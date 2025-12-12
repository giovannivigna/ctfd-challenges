#!/bin/bash
IMAGE=blinddate
PORT=8443
docker run -p ${PORT}:${PORT} ${IMAGE}
