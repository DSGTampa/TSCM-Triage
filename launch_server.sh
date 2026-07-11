#!/bin/bash
# DSG TSCM Triage — Server Launcher
#
# Usage:
#   bash launch_server.sh
#   bash launch_server.sh --cases-path /media/usb/DSG-TSCM/cases
#
# --cases-path redirects all case output to an external drive. This is
# recommended for Raspberry Pi deployments to protect the SD card from the
# write wear caused by scans and packet captures.

CASES_PATH_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cases-path)
      CASES_PATH_ARG="$2"
      shift 2
      ;;
    --cases-path=*)
      CASES_PATH_ARG="${1#*=}"
      shift
      ;;
    *)
      echo "[DSG] Unknown option: $1"
      echo "      Usage: bash launch_server.sh [--cases-path /path/to/drive]"
      exit 1
      ;;
  esac
done

if [[ -n "$CASES_PATH_ARG" ]]; then
  export CASES_PATH="$CASES_PATH_ARG"
else
  export CASES_PATH="$HOME/DSG-TSCM/cases"
fi

# Make sure the target exists (also surfaces a missing/unmounted drive early)
mkdir -p "$CASES_PATH" 2>/dev/null

cd "$HOME/dsg-tscm"
echo "[DSG] Starting TSCM Triage server at http://127.0.0.1:5555"
echo "[DSG] Cases path: $CASES_PATH"
python3 server.py &
SERVER_PID=$!
sleep 1.5
if command -v chromium &>/dev/null; then
  chromium --app="http://127.0.0.1:5555" --window-size=1200,900     --disable-gpu-sandbox --disable-software-rasterizer     2>/dev/null &
elif command -v firefox &>/dev/null; then
  firefox "http://127.0.0.1:5555" &
fi
echo "[DSG] Server PID: $SERVER_PID — kill with: kill $SERVER_PID"
