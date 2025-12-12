#!/bin/bash
export PORT=5544
gunicorn --log-level DEBUG -b 0.0.0.0:${PORT} app:app