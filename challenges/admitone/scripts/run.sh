#!/bin/bash
IMAGE="admitone"
PORT=5544
docker run -p ${PORT}:${PORT} ${IMAGE}
