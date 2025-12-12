#!/bin/bash
IMAGE="secretword2"
PORT=12321
docker run -p ${PORT}:${PORT} ${IMAGE}
