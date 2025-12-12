#!/bin/bash
export PORT=8443
gunicorn --log-level DEBUG -b 0.0.0.0:${PORT} app:app