#!/bin/bash
# ============================================================
#  DSG TSCM TRIAGE v1.7.0 — Kali Linux Installer
#  Surveillance Specialist Group, LLC
#  d/b/a Data Specialist Group
#  www.dataspecialistgroup.com
# ============================================================
RED='\033[0;31m';GREEN='\033[0;32m';CYAN='\033[0;36m';WHITE='\033[1;37m';YELLOW='\033[1;33m';NC='\033[0m'
clear
echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       SURVEILLANCE SPECIALIST GROUP, LLC             ║"
echo "  ║          d/b/a  DATA SPECIALIST GROUP                ║"
echo "  ║       DSG TSCM TRIAGE v1.7.0 — INSTALLER            ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTML_SRC="$SCRIPT_DIR/dsg_tscm_triage.html"
if [[ ! -f "$HTML_SRC" ]]; then
  echo -e "${RED}[!] dsg_tscm_triage.html not found in the same folder as this script.${NC}"
  exit 1
fi
echo -e "${GREEN}[✓]${NC} Found: $HTML_SRC"

INSTALL_DIR="$HOME/dsg-tscm"
mkdir -p "$INSTALL_DIR"
cp "$HTML_SRC" "$INSTALL_DIR/dsg_tscm_triage.html"
echo -e "${GREEN}[✓]${NC} Installed to: $INSTALL_DIR"

# ── Launcher ────────────────────────────────────────────────
cat > "$INSTALL_DIR/launch.sh" << 'LAUNCHER'
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
LAUNCHER
chmod +x "$INSTALL_DIR/launch.sh"
echo -e "${GREEN}[✓]${NC} Launcher created"

# ── Desktop shortcut ─────────────────────────────────────────
DDIR="$HOME/.local/share/applications"
mkdir -p "$DDIR"
cat > "$DDIR/dsg-tscm-triage.desktop" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=DSG TSCM Triage
Comment=Surveillance Specialist Group — TSCM Network Intelligence v1.7.0
Exec=$INSTALL_DIR/launch.sh
Icon=network-workgroup
Terminal=false
Categories=Network;Security;
Keywords=TSCM;surveillance;forensics;network;DSG;
DESKTOP
chmod +x "$DDIR/dsg-tscm-triage.desktop"
echo -e "${GREEN}[✓]${NC} Desktop shortcut created"

# ── Shell alias ───────────────────────────────────────────────
ALIAS_LINE="alias dsg-tscm='bash \$HOME/dsg-tscm/launch.sh'"
for RC in "$HOME/.zshrc" "$HOME/.bashrc"; do
  if [[ -f "$RC" ]]; then
    if grep -q "alias dsg-tscm" "$RC" 2>/dev/null; then
      sed -i 's|alias dsg-tscm=.*|'"$ALIAS_LINE"'|' "$RC"
      echo -e "${GREEN}[✓]${NC} Updated alias in $RC"
    else
      echo "" >> "$RC"
      echo "# DSG TSCM Triage v1.7.0" >> "$RC"
      echo "$ALIAS_LINE" >> "$RC"
      echo -e "${GREEN}[✓]${NC} Alias added to $RC"
    fi
  fi
done

# ── OUI permission fix ───────────────────────────────────────
if [[ -f /usr/share/arp-scan/ieee-oui.txt ]]; then
  chmod 644 /usr/share/arp-scan/ieee-oui.txt 2>/dev/null
  chmod 644 /usr/share/arp-scan/mac-vendor.txt 2>/dev/null
  echo -e "${GREEN}[✓]${NC} arp-scan OUI database permissions fixed"
else
  echo -e "${YELLOW}[!]${NC} arp-scan OUI files not found — install with: sudo apt install arp-scan"
fi

# ── Flask server ─────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[?]${NC} Install Flask server? (enables live interface detection and local API)"
read -rp "    Install Flask? [y/N]: " FLASK_CHOICE
if [[ "$FLASK_CHOICE" =~ ^[Yy]$ ]]; then
  pip3 install flask --break-system-packages --quiet 2>/dev/null
  cat > "$INSTALL_DIR/server.py" << 'PYSERVER'
#!/usr/bin/env python3
"""
DSG TSCM Triage v1.7.0 — Local Flask Server
Surveillance Specialist Group, LLC
Run: python3 ~/dsg-tscm/server.py
Access: http://127.0.0.1:5555
"""
import os, re, socket, subprocess
from flask import Flask, send_file, jsonify
from flask_cors import CORS

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))

try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    # Add manual CORS headers if flask_cors not available
    @app.after_request
    def add_cors(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

@app.route('/')
def index():
    return send_file(os.path.join(BASE, 'dsg_tscm_triage.html'))

@app.route('/api/interfaces')
def interfaces():
    # Virtual/internal interfaces to exclude
    EXCLUDE = ('lo', 'docker', 'veth', 'br-', 'virbr', 'vmnet', 'dummy', 'bond', 'ovs')
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        wired = []
        wireless = []
        current = None
        ip_info = None
        for line in result.stdout.split('\n'):
            m = re.match(r'^\d+:\s+(\S+?)[@:]', line)
            if m:
                # Save previous interface before moving on
                if current and not any(current.startswith(ex) for ex in EXCLUDE):
                    if current.startswith('wlan') and not 'mon' in current:
                        wireless.append({'name': current,
                                         'ip': ip_info['ip'] if ip_info else 'no IP',
                                         'subnet': ip_info['subnet'] if ip_info else '',
                                         'type': 'wireless'})
                    elif ip_info and not current.startswith('wlan'):
                        wired.append({'name': current, 'ip': ip_info['ip'],
                                      'subnet': ip_info['subnet'], 'type': 'wired'})
                current = m.group(1)
                ip_info = None
            ip_m = re.match(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if ip_m and current:
                ip = ip_m.group(1)
                pfx = ip_m.group(2)
                parts = ip.split('.')
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{pfx}"
                ip_info = {'ip': ip, 'subnet': subnet}
        # Handle last interface
        if current and not any(current.startswith(ex) for ex in EXCLUDE):
            if current.startswith('wlan') and 'mon' not in current:
                wireless.append({'name': current,
                                 'ip': ip_info['ip'] if ip_info else 'no IP',
                                 'subnet': ip_info['subnet'] if ip_info else '',
                                 'type': 'wireless'})
            elif ip_info and not current.startswith('wlan'):
                wired.append({'name': current, 'ip': ip_info['ip'],
                              'subnet': ip_info['subnet'], 'type': 'wired'})
        return jsonify({'wired': wired, 'wireless': wireless,
                        'interfaces': wired + wireless})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/local-ip')
def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return jsonify({'local_ip': ip})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print('\n  DSG TSCM Triage v1.7.0 — Flask Server')
    print('  http://127.0.0.1:5555\n')
    app.run(host='127.0.0.1', port=5555, debug=False)
PYSERVER
  pip3 install flask-cors --break-system-packages --quiet 2>/dev/null

  cat > "$INSTALL_DIR/launch_server.sh" << 'SLAUNCH'
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
SLAUNCH
  chmod +x "$INSTALL_DIR/launch_server.sh" "$INSTALL_DIR/server.py"
  echo -e "${GREEN}[✓]${NC} Flask server installed"
  echo -e "${GREEN}[✓]${NC} Launch with server: bash ~/dsg-tscm/launch_server.sh"
fi

# ── DSG case directory ────────────────────────────────────────
mkdir -p "$HOME/DSG-TSCM/cases"
echo -e "${GREEN}[✓]${NC} Created: ~/DSG-TSCM/cases/ (case folder root)"

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          DSG TSCM TRIAGE v1.7.0 — INSTALLED         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${WHITE}Launch (no server):${NC}  bash ~/dsg-tscm/launch.sh"
[[ "$FLASK_CHOICE" =~ ^[Yy]$ ]] && echo -e "  ${WHITE}Launch (with server):${NC} bash ~/dsg-tscm/launch_server.sh"
echo -e "  ${WHITE}Shell alias:${NC}          source ~/.zshrc && dsg-tscm"
echo -e "  ${WHITE}Desktop:${NC}              Applications → Network → DSG TSCM Triage"
echo -e "  ${WHITE}Case folder root:${NC}     ~/DSG-TSCM/cases/"
echo ""
echo -e "  ${GREEN}Surveillance Specialist Group, LLC${NC}"
echo -e "  ${GREEN}dataspecialistgroup.com  ·  (877) 787-7075${NC}"
echo ""

# ── Wireshark / tshark capture permissions ───────────────────
echo ""
echo -e "${CYAN}[i]${NC} Configuring tshark capture permissions..."
if dpkg -l wireshark-common &>/dev/null 2>&1; then
  echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
  sudo dpkg-reconfigure -f noninteractive wireshark-common 2>/dev/null
  sudo usermod -aG wireshark "$USER" 2>/dev/null
  echo -e "${GREEN}[✓]${NC} wireshark group configured — logout/login to activate"
  echo -e "${YELLOW}[!]${NC} After reinstall, run: newgrp wireshark"
  echo -e "${YELLOW}[!]${NC} Then use tshark WITHOUT sudo for captures"
else
  echo -e "${YELLOW}[!]${NC} wireshark-common not found — install with:"
  echo -e "    sudo apt install wireshark-common tshark -y"
fi
