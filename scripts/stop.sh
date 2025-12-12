#!/bin/bash

source scripts/challenge.sh

# Get the container IDs of all running containers based on the specified image
CONTAINER_IDS=$(docker ps -q --filter ancestor=${CHALLENGE_NAME})

# Check if any containers were found
if [ -z "$CONTAINER_IDS" ]; then
    echo "No running containers found for image '${CHALLENGE_NAME}'"
    exit 0
fi

# Stop each container
for CONTAINER_ID in $CONTAINER_IDS
do
    echo "Stopping container $CONTAINER_ID..."
    docker stop $CONTAINER_ID
done

echo "All containers associated with the image '${CHALLENGE_NAME}' have been stopped."
