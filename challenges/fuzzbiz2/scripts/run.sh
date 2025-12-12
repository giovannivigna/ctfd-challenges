#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Runs the Docker container
docker run -p ${PORT}:${PORT} ${IMAGE}
