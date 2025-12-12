#!/bin/bash
export PORT=12721
gunicorn --log-level DEBUG -b 0.0.0.0:${PORT} app:app