#!/bin/bash
IMAGE="sox40basic"
PORT=11221
docker run -p ${PORT}:${PORT} ${IMAGE}
