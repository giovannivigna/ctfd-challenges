#!/bin/bash

set -euo pipefail

source scripts/challenge.sh

rm -rf "${CHALLENGE_NAME}-bundle" "${CHALLENGE_NAME}-bundle.tgz"

mkdir -p "${CHALLENGE_NAME}-bundle/flag"
echo "ictf{ThisIsaFakeFlagFor${CHALLENGE_NAME}}" > "${CHALLENGE_NAME}-bundle/flag/flag"

mkdir -p "${CHALLENGE_NAME}-bundle/dist"

make -C src clean all
cp "src/${CHALLENGE_NAME}" "${CHALLENGE_NAME}-bundle/dist/${CHALLENGE_NAME}"
cp "player_README.md" "${CHALLENGE_NAME}-bundle/dist/README.md"

tar cvzf "${CHALLENGE_NAME}-bundle.tgz" "${CHALLENGE_NAME}-bundle"
rm -rf "${CHALLENGE_NAME}-bundle"

