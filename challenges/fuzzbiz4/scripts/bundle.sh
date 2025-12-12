#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

# Creates a tarball of the challenge bundle
mkdir ${IMAGE}-bundle
mkdir ${IMAGE}-bundle/flag
echo "ictf{ThisIsaFakeFlagFor${IMAGE}}" > ${IMAGE}-bundle/flag/flag
mkdir ${IMAGE}-bundle/ro
mkdir ${IMAGE}-bundle/rw
cp -R ./src ${IMAGE}-bundle/
cp -R ./scripts ${IMAGE}-bundle/
cp Dockerfile ${IMAGE}-bundle/
tar cvzf ${IMAGE}-bundle.tgz ${IMAGE}-bundle
rm -fr ${IMAGE}-bundle

