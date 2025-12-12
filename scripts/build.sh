#!/bin/bash

source scripts/challenge.sh
docker build -t ${CHALLENGE_NAME} .
