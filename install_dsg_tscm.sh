#!/bin/bash
# ============================================================
#  DSG TSCM TRIAGE — Kali Linux Installer
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
echo "  ║          DSG TSCM TRIAGE — INSTALLER                 ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/dsg-tscm"

# Files that make up the project
PROJECT_FILES=(dsg_tscm_triage.html server.py launch.sh launch_server.sh analyze_capture.sh)

# Sanity check — the HTML must live alongside this installer
if [[ ! -f "$SCRIPT_DIR/dsg_tscm_triage.html" ]]; then
  echo -e "${RED}[!] dsg_tscm_triage.html not found in the same folder as this script.${NC}"
  echo -e "${RED}    Run this installer from inside the project directory.${NC}"
  exit 1
fi
echo -e "${GREEN}[✓]${NC} Project source: $SCRIPT_DIR"

# ── Track results for the final summary ─────────────────────
APT_STATUS="skipped"
PIP_CORE_STATUS="skipped"
declare -a PIP_OPT_OK=()
declare -a PIP_OPT_FAIL=()

# ============================================================
#  1. APT UPDATE
# ============================================================
echo ""
echo -e "${CYAN}[1/11]${NC} Updating apt package lists..."
sudo apt update

# ============================================================
#  2. APT PACKAGES (single command)
# ============================================================
echo ""
echo -e "${CYAN}[2/11]${NC} Installing system prerequisites..."
APT_PKGS="nmap arp-scan netdiscover aircrack-ng kismet tshark wireshark wireshark-common eyewitness docker.io hackrf soapysdr-tools rtl-sdr net-tools curl wget python3-pip"
# Preseed wireshark setuid answer so tshark install is non-interactive
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
if sudo DEBIAN_FRONTEND=noninteractive apt install -y $APT_PKGS; then
  APT_STATUS="installed"
  echo -e "${GREEN}[✓]${NC} System packages installed"
else
  APT_STATUS="partial"
  echo -e "${YELLOW}[!]${NC} One or more apt packages failed — continuing"
fi

# ============================================================
#  3. PIP PACKAGES (core — required)
# ============================================================
echo ""
echo -e "${CYAN}[3/11]${NC} Installing core Python packages..."
if pip3 install flask flask-cors wsdiscovery --break-system-packages; then
  PIP_CORE_STATUS="installed"
  echo -e "${GREEN}[✓]${NC} flask, flask-cors, wsdiscovery installed"
else
  PIP_CORE_STATUS="failed"
  echo -e "${RED}[!]${NC} Core Python packages failed to install"
fi

# ============================================================
#  4. PIP PACKAGES (optional OSINT — may fail, that's OK)
# ============================================================
echo ""
echo -e "${CYAN}[4/11]${NC} Installing optional OSINT tools (failures are non-fatal)..."
for PKG in holehe phoneinfoga sherlock-project; do
  echo -e "${WHITE}    → $PKG${NC}"
  if pip3 install "$PKG" --break-system-packages 2>/dev/null; then
    PIP_OPT_OK+=("$PKG")
    echo -e "${GREEN}[✓]${NC} $PKG installed"
  else
    PIP_OPT_FAIL+=("$PKG")
    echo -e "${YELLOW}[!]${NC} $PKG not installed (skipped)"
  fi
done

# ============================================================
#  5. WIRESHARK / TSHARK CAPTURE PERMISSIONS
# ============================================================
echo ""
echo -e "${CYAN}[5/11]${NC} Configuring tshark/wireshark capture permissions..."
if dpkg -l wireshark-common &>/dev/null 2>&1; then
  echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
  sudo dpkg-reconfigure -f noninteractive wireshark-common 2>/dev/null
  sudo usermod -aG wireshark "$USER" 2>/dev/null
  echo -e "${GREEN}[✓]${NC} wireshark group configured for $USER (logout/login to activate)"
else
  echo -e "${YELLOW}[!]${NC} wireshark-common not present — skipping capture permission fix"
fi

# ============================================================
#  6. ARP-SCAN OUI DATABASE PERMISSIONS
# ============================================================
echo ""
echo -e "${CYAN}[6/11]${NC} Fixing arp-scan OUI database permissions..."
sudo chmod 644 /usr/share/arp-scan/*.txt 2>/dev/null
echo -e "${GREEN}[✓]${NC} OUI database permissions fixed"

# ============================================================
#  7. CREATE REQUIRED DIRECTORIES
# ============================================================
echo ""
echo -e "${CYAN}[7/11]${NC} Creating application directories..."
mkdir -p "$HOME/dsg-tscm" "$HOME/DSG-TSCM/cases"
echo -e "${GREEN}[✓]${NC} ~/dsg-tscm/ and ~/DSG-TSCM/cases/ ready"

# ============================================================
#  8. COPY PROJECT FILES
# ============================================================
echo ""
echo -e "${CYAN}[8/11]${NC} Copying project files to $INSTALL_DIR ..."
for F in "${PROJECT_FILES[@]}"; do
  if [[ -f "$SCRIPT_DIR/$F" ]]; then
    cp "$SCRIPT_DIR/$F" "$INSTALL_DIR/$F"
    echo -e "${GREEN}[✓]${NC} $F"
  else
    echo -e "${YELLOW}[!]${NC} $F not found in source — skipped"
  fi
done

# ── Launcher (HTML only, no server) ──────────────────────────
cat > "$INSTALL_DIR/launch.sh" << 'LAUNCHER'
#!/bin/bash
HTML="$HOME/dsg-tscm/dsg_tscm_triage.html"
if command -v chromium &>/dev/null; then
  chromium --app="file://$HTML" --window-size=1200,900 --disable-gpu-sandbox --disable-software-rasterizer 2>/dev/null &
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

# ── Desktop shortcut ─────────────────────────────────────────
DDIR="$HOME/.local/share/applications"
mkdir -p "$DDIR"
cat > "$DDIR/dsg-tscm-triage.desktop" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=DSG TSCM Triage
Comment=Surveillance Specialist Group — TSCM Network Intelligence
Exec=$INSTALL_DIR/launch.sh
Icon=network-workgroup
Terminal=false
Categories=Network;Security;
Keywords=TSCM;surveillance;forensics;network;DSG;
DESKTOP
chmod +x "$DDIR/dsg-tscm-triage.desktop"
echo -e "${GREEN}[✓]${NC} Desktop shortcut created"

# ============================================================
#  9. MAKE SCRIPTS EXECUTABLE
# ============================================================
echo ""
echo -e "${CYAN}[9/11]${NC} Setting executable permissions..."
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null
chmod +x "$INSTALL_DIR/server.py" 2>/dev/null
echo -e "${GREEN}[✓]${NC} Scripts are executable"

# ============================================================
#  10. SHELL ALIAS (zsh + bash)
# ============================================================
echo ""
echo -e "${CYAN}[10/11]${NC} Configuring 'dsg-tscm' shell alias..."
ALIAS_LINE="alias dsg-tscm='bash \$HOME/dsg-tscm/launch.sh'"
for RC in "$HOME/.zshrc" "$HOME/.bashrc"; do
  touch "$RC"
  if grep -q "alias dsg-tscm" "$RC" 2>/dev/null; then
    sed -i 's|alias dsg-tscm=.*|'"$ALIAS_LINE"'|' "$RC"
    echo -e "${GREEN}[✓]${NC} Updated alias in $RC"
  else
    echo "" >> "$RC"
    echo "# DSG TSCM Triage" >> "$RC"
    echo "$ALIAS_LINE" >> "$RC"
    echo -e "${GREEN}[✓]${NC} Alias added to $RC"
  fi
done

# ============================================================
#  11. SUMMARY
# ============================================================
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║            DSG TSCM TRIAGE — INSTALL COMPLETE        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${WHITE}System packages (apt):${NC}   $APT_STATUS"
echo -e "  ${WHITE}Core Python (pip):${NC}       $PIP_CORE_STATUS  (flask, flask-cors, wsdiscovery)"
if [[ ${#PIP_OPT_OK[@]} -gt 0 ]]; then
  echo -e "  ${WHITE}OSINT tools installed:${NC}   ${PIP_OPT_OK[*]}"
fi
if [[ ${#PIP_OPT_FAIL[@]} -gt 0 ]]; then
  echo -e "  ${WHITE}OSINT tools skipped:${NC}     ${YELLOW}${PIP_OPT_FAIL[*]}${NC}"
fi
echo ""
echo -e "  ${WHITE}Installed to:${NC}            $INSTALL_DIR"
echo -e "  ${WHITE}Case folder root:${NC}        ~/DSG-TSCM/cases/"
echo ""
echo -e "  ${WHITE}Launch (no server):${NC}      bash ~/dsg-tscm/launch.sh"
echo -e "  ${WHITE}Launch (with server):${NC}    bash ~/dsg-tscm/launch_server.sh"
echo -e "  ${WHITE}Shell alias:${NC}             source ~/.zshrc && dsg-tscm"
echo -e "  ${WHITE}Desktop:${NC}                 Applications → Network → DSG TSCM Triage"
echo ""
echo -e "  ${YELLOW}NEXT STEPS:${NC}"
echo -e "    ${WHITE}1.${NC} Log out and back in (or reboot) to activate the"
echo -e "       ${WHITE}wireshark${NC} group so tshark can capture without sudo."
echo -e "       Quick check in a new shell:  ${WHITE}groups | grep wireshark${NC}"
echo -e "    ${WHITE}2.${NC} Reload your shell to pick up the alias:  ${WHITE}source ~/.zshrc${NC}"
echo -e "    ${WHITE}3.${NC} Launch:  ${WHITE}dsg-tscm${NC}"
echo ""
echo -e "  ${GREEN}Surveillance Specialist Group, LLC${NC}"
echo -e "  ${GREEN}dataspecialistgroup.com  ·  (877) 787-7075${NC}"
echo ""
