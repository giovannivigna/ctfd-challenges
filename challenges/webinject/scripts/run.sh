#!/bin/bash
IMAGE="webinject"
PORT=5000
docker run -p ${PORT}:${PORT} ${IMAGE}
