#!/bin/bash
HTML="$HOME/dsg-tscm/dsg_tscm_triage.html"
if command -v chromium &>/dev/null; then
  chromium --app="file://$HTML" --window-size=1200,900   --disable-gpu-sandbox --disable-software-rasterizer   2>/dev/null &
elif command -v chromium-browser &>/dev/null; then
  chromium-browser --app="file://$HTML" --window-size=1200,900 &
elif command -v firefox &>/dev/null; then
  firefox "file://$HTML" &
elif command -v firefox-esr &>/dev/null; then
  firefox-esr "file://$HTML" &
else
  xdg-open "file://$HTML" &
fi
