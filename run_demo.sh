#!/usr/bin/env bash
# Demo mode: fictional client, fixture data, no network traffic. Starts clean every time.
set -euo pipefail
cd "$(dirname "$0")"
export RUNNER_DEMO=1
export RUNNER_DATA_DIR="${RUNNER_DATA_DIR:-./demo-data}"
export RUNNER_SECRET_KEY="${RUNNER_SECRET_KEY:-demo-only-not-secret}"
echo "CyberHealth Runner (demo) on http://localhost:${PORT:-8000}  (Ctrl+C to stop)"
exec python3 app.py
