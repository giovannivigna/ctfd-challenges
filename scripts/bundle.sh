#!/bin/bash

source scripts/challenge.sh
mkdir ${CHALLENGE_NAME}-bundle
mkdir ${CHALLENGE_NAME}-bundle/flag
echo "ictf{ThisIsaFakeFlagFor${CHALLENGE_NAME}}" > ${CHALLENGE_NAME}-bundle/flag/flag
mkdir ${CHALLENGE_NAME}-bundle/ro
mkdir ${CHALLENGE_NAME}-bundle/rw
cp -R ./src ${CHALLENGE_NAME}-bundle/
cp -R ./scripts ${CHALLENGE_NAME}-bundle/
cp Dockerfile ${CHALLENGE_NAME}-bundle/

tar cvzf ${CHALLENGE_NAME}-bundle.tgz ${CHALLENGE_NAME}-bundle
rm -fr ${CHALLENGE_NAME}-bundle


