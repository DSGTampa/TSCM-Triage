#!/bin/bash
# DSG TSCM Triage — start a fresh dual-band Kismet capture for a new location.
#
# Puts the Wi-Fi adapter(s) into monitor mode and launches Kismet across ALL
# 2.4GHz + 5GHz channels, writing the log where the Network Validation tool
# looks for it (~<user>/Kismet-*.kismet). Must run as root:
#
#     sudo bash start_kismet.sh
#
# Overrides via env: TSCM_WIFI (primary iface, default wlan1),
# TSCM_WIFI5 (5GHz iface, default wlan2), TSCM_KISMET_PREFIX (log path prefix).
set -u

PRIMARY="${TSCM_WIFI:-wlan1}"
SECONDARY="${TSCM_WIFI5:-wlan2}"
# Write to the invoking (non-root) user's home so the app — running as that
# user — finds it via its ~/*.kismet default search.
OWNER="${SUDO_USER:-$(whoami)}"
LOG_PREFIX="${TSCM_KISMET_PREFIX:-/home/${OWNER}/Kismet}"

CH_24="1,2,3,4,5,6,7,8,9,10,11,12,13,14"
CH_5="36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165"
CH_ALL="${CH_24},${CH_5}"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root (it sets monitor mode). Try: sudo bash $0"
  exit 1
fi

mon_up() {  # $1 = device, $2 = monitor name
  ip link set "$1" down 2>/dev/null
  iw dev "$1" set type monitor 2>/dev/null
  ip link set "$1" up 2>/dev/null
  iw dev "$1" set name "$2" 2>/dev/null || true
}

SOURCES=()
if ip link show "$SECONDARY" >/dev/null 2>&1; then
  echo "// Two adapters: $PRIMARY (2.4GHz) + $SECONDARY (5GHz)"
  mon_up "$PRIMARY" "${PRIMARY}mon"
  mon_up "$SECONDARY" "${SECONDARY}mon"
  SOURCES+=(-c "${PRIMARY}mon:name=wifi24,channels=\"${CH_24}\"")
  SOURCES+=(-c "${SECONDARY}mon:name=wifi5,channels=\"${CH_5}\"")
else
  echo "// Single adapter: $PRIMARY full-hop 2.4GHz + 5GHz"
  mon_up "$PRIMARY" "${PRIMARY}mon"
  SOURCES+=(-c "${PRIMARY}mon:name=wifiall,channels=\"${CH_ALL}\"")
fi

echo "// Log prefix: ${LOG_PREFIX}   (owner: ${OWNER})"
# --log-title dsg_tscm tags THIS capture as ours so the app can tell its own
# Kismet apart from any other product's Kismet running on the same machine.
echo "// Starting Kismet: kismet ${SOURCES[*]} --no-ncurses --log-prefix ${LOG_PREFIX} --log-title dsg_tscm"
exec kismet "${SOURCES[@]}" --no-ncurses --log-prefix "${LOG_PREFIX}" --log-title dsg_tscm
