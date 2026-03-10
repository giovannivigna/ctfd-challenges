#!/bin/bash
export PORT=8862
# Single worker to avoid SQLite "database is locked" with concurrent requests
gunicorn --log-level DEBUG -w 1 -b 0.0.0.0:${PORT} app:app