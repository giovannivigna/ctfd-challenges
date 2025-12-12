#!/bin/bash
SERVICE="getbuff"
mkdir ${SERVICE}-bundle
mkdir ${SERVICE}-bundle/flag
echo "ictf{ThisIsaFakeFlagFor${SERVICE}}" > ${SERVICE}-bundle/flag/flag.txt
mkdir ${SERVICE}-bundle/ro
mkdir ${SERVICE}-bundle/rw
cp -R ./src ${SERVICE}-bundle/
cp -R ./scripts ${SERVICE}-bundle/
cp Dockerfile ${SERVICE}-bundle/

tar cvzf ${SERVICE}-bundle.tgz ${SERVICE}-bundle
# rm -fr ${SERVICE}-bundle

