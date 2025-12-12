#!/bin/bash
IMAGE="loggable2"
PORT=4343
docker run -p ${PORT}:${PORT} ${IMAGE}
