#!/bin/bash
export PORT=1526
gunicorn --log-level DEBUG -b 0.0.0.0:${PORT} app:app