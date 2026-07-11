#!/bin/bash
# DSG TSCM Triage — Update / Redeploy Helper
# Pulls the latest code (if run inside the git clone) and deploys the app
# files to the runtime location (~/dsg-tscm), then restarts the Flask server
# if it was running.
#
# Usage:  bash update.sh
set -u

INSTALL_DIR="$HOME/dsg-tscm"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; WHITE='\033[1;37m'; NC='\033[0m'

echo -e "${WHITE}== DSG TSCM Triage — Update ==${NC}"

# 1. Pull latest if this is a git checkout
if git -C "$SRC_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo -e "${WHITE}[1/4]${NC} Pulling latest from GitHub..."
  git -C "$SRC_DIR" pull --ff-only || echo -e "${YELLOW}[!]${NC} git pull skipped/failed — continuing with local files"
else
  echo -e "${YELLOW}[1/4]${NC} Not a git checkout — skipping pull, using local files"
fi

# 2. Ensure runtime dir exists
mkdir -p "$INSTALL_DIR"

# 3. Deploy app files
echo -e "${WHITE}[2/4]${NC} Deploying files to ${INSTALL_DIR}..."
for f in dsg_tscm_triage.html server.py analyze_capture.sh launch.sh launch_server.sh; do
  if [ -f "$SRC_DIR/$f" ]; then
    cp "$SRC_DIR/$f" "$INSTALL_DIR/$f"
    echo -e "   ${GREEN}✓${NC} $f"
  fi
done
chmod +x "$INSTALL_DIR"/*.sh "$INSTALL_DIR/server.py" 2>/dev/null || true

# 4. Restart the Flask server only if it was already running
echo -e "${WHITE}[3/4]${NC} Checking Flask server..."
if pgrep -f "python3 .*server.py" >/dev/null 2>&1; then
  echo -e "   ${YELLOW}•${NC} Server running — restarting with new version"
  pkill -f "python3 .*server.py" 2>/dev/null
  sleep 1
  ( cd "$INSTALL_DIR" && nohup python3 server.py >/dev/null 2>&1 & )
  sleep 1
  if pgrep -f "python3 .*server.py" >/dev/null 2>&1; then
    echo -e "   ${GREEN}✓${NC} Server restarted at http://127.0.0.1:5555"
  else
    echo -e "   ${RED}✗${NC} Server did not come back — start it with: bash ${INSTALL_DIR}/launch_server.sh"
  fi
else
  echo -e "   ${YELLOW}•${NC} Server not running — launch when ready: bash ${INSTALL_DIR}/launch_server.sh"
fi

echo -e "${WHITE}[4/4]${NC} ${GREEN}Update complete.${NC} Hard-refresh the browser (Ctrl+Shift+R) to load the new UI."
