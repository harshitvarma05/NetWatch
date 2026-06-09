#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8010}"
URL="http://127.0.0.1:${PORT}"

cd "$ROOT"

echo "NetWatch IDS startup"
echo "Project: $ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but was not found."
  exit 1
fi

if ! python3 - <<'PY' >/dev/null 2>&1
import joblib
import numpy
import pandas
import sklearn
PY
then
  echo "Installing Python ML dependencies from requirements.txt..."
  python3 -m pip install -r requirements.txt
fi

if command -v c++ >/dev/null 2>&1; then
  echo "Checking C++ packet collector..."
  if ! c++ -std=c++17 -O2 -Wall -Wextra collector/live_collector.cpp -lpcap -o collector/live_collector; then
    echo "Collector build failed; the Python fallback collector can still run."
  fi
else
  echo "C++ compiler not found; the Python fallback collector can still run."
fi

if command -v lsof >/dev/null 2>&1 && lsof -ti "tcp:${PORT}" >/dev/null 2>&1; then
  PID="$(lsof -ti "tcp:${PORT}" | head -n 1)"
  COMMAND="$(ps -p "$PID" -o command= 2>/dev/null || true)"
  LISTENER="$(lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1}')"
  if [[ "$COMMAND" == *"python3 app.py"* ]] || [[ "$COMMAND" == *"python app.py"* ]]; then
    echo "IDS is already running at ${URL}"
    echo "Dashboard: ${URL}"
    exit 0
  fi
  if [[ "$LISTENER" == "Python"* ]] || [[ "$LISTENER" == "python"* ]]; then
    echo "A Python server is already listening on ${URL}"
    echo "Dashboard: ${URL}"
    exit 0
  fi
  if command -v curl >/dev/null 2>&1 && curl -fsS "${URL}/api/health" >/dev/null 2>&1; then
    echo "IDS is already running at ${URL}"
    echo "Dashboard: ${URL}"
    exit 0
  fi
  echo "Port ${PORT} is already in use by another process."
  echo "Run with another port, for example: PORT=8011 ./run.sh"
  exit 1
fi

echo "Starting IDS backend..."
echo "Dashboard: ${URL}"
echo "Press Ctrl+C to stop."
PORT="$PORT" python3 app.py
