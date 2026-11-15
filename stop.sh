#!/usr/bin/env bash
cd "$(dirname "$0")"
if [ -f server.pid ]; then
  PID=$(cat server.pid)
  kill $PID 2>/dev/null || true
  rm -f server.pid
  echo "Agents Hub stopped (PID: $PID)"
else
  pkill -f "uvicorn main:app --host 0.0.0.0 --port 8000" || true
  echo "Agents Hub stopped"
fi
