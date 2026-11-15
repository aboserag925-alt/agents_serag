#!/usr/bin/env bash
cd "$(dirname "$0")"
mkdir -p logs
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 </dev/null >> logs/server.log 2>&1 &
PID=$!
echo $PID > server.pid
echo "Agents Hub started on http://localhost:8000 (PID: $PID)"
