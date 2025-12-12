#!/bin/bash
IMAGE="sympathy"
PORT=40404
docker run -p ${PORT}:${PORT} ${IMAGE}
