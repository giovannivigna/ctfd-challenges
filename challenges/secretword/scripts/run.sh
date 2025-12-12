#!/bin/bash
IMAGE="secretword"
PORT=45454
docker run -p ${PORT}:${PORT} ${IMAGE}
