#!/bin/bash

set -euo pipefail

source scripts/challenge.sh

rm -rf "${CHALLENGE_NAME}-bundle" "${CHALLENGE_NAME}-bundle.tgz"

mkdir -p "${CHALLENGE_NAME}-bundle/flag"
echo "ictf{ThisIsaFakeFlagFor${CHALLENGE_NAME}}" > "${CHALLENGE_NAME}-bundle/flag/flag"

mkdir -p "${CHALLENGE_NAME}-bundle/ro"
mkdir -p "${CHALLENGE_NAME}-bundle/src"
mkdir -p "${CHALLENGE_NAME}-bundle/scripts"

cp -R ./ro/* "${CHALLENGE_NAME}-bundle/ro/"
cp -R ./src/* "${CHALLENGE_NAME}-bundle/src/"
cp -R ./scripts/* "${CHALLENGE_NAME}-bundle/scripts/"
cp ./Dockerfile ./README.md ./challenge.yml "${CHALLENGE_NAME}-bundle/"

tar cvzf "${CHALLENGE_NAME}-bundle.tgz" "${CHALLENGE_NAME}-bundle"
rm -rf "${CHALLENGE_NAME}-bundle"

