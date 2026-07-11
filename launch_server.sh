#!/bin/bash
cd "$HOME/dsg-tscm"
echo "[DSG] Starting TSCM Triage server at http://127.0.0.1:5555"
python3 server.py &
SERVER_PID=$!
sleep 1.5
if command -v chromium &>/dev/null; then
  chromium --app="http://127.0.0.1:5555" --window-size=1200,900     --disable-gpu-sandbox --disable-software-rasterizer     2>/dev/null &
elif command -v firefox &>/dev/null; then
  firefox "http://127.0.0.1:5555" &
fi
echo "[DSG] Server PID: $SERVER_PID — kill with: kill $SERVER_PID"
