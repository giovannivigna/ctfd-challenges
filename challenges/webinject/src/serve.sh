#!/bin/bash
export PORT=8862
gunicorn --log-level DEBUG -b 0.0.0.0:${PORT} app:app