#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Get the container IDs of all running containers based on the specified image
docker ps -q --filter ancestor=$IMAGE
