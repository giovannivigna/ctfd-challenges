#!/bin/bash

source scripts/challenge.sh
docker run -p ${CHALLENGE_PORT}:${CHALLENGE_PORT} ${CHALLENGE_NAME}
