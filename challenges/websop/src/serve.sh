#!/bin/bash
set -euo pipefail

export PORT="${PORT:-8863}"

# Keep a single worker and avoid threads (sqlite connection is thread-bound)
exec gunicorn --workers 1 --worker-class sync --log-level DEBUG -b 0.0.0.0:"${PORT}" app:app

