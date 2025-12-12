#!/bin/bash
IMAGE="doomtemple"
PORT=1526
docker run -p ${PORT}:${PORT} ${IMAGE}
