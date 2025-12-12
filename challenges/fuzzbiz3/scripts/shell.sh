#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Get a shell in the running container
docker exec -it $1 /bin/bash

