#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Builds the Docker image
docker build -t ${IMAGE} .
