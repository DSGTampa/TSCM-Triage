#!/bin/bash
#
# DSG TSCM Triage — analyze_capture.sh
# Surveillance Specialist Group, LLC
#
# Parses airodump-ng CSV output and produces a color-coded flagged report,
# matching known surveillance-camera / covert-device OUIs and SSID patterns.
#
# Usage:
#   ./analyze_capture.sh <airodump.csv> [case_output_folder]
#
# Example:
#   ./analyze_capture.sh ~/DSG-TSCM/cases/test5/wireless/post_deauth-01.csv \
#                        ~/DSG-TSCM/cases/test5/scans/
#

# ---------------------------------------------------------------------------
# Args & validation
# ---------------------------------------------------------------------------
CSV="${1:-}"

if [ -z "$CSV" ]; then
  echo "Usage: $0 <airodump.csv> [case_output_folder]" >&2
  exit 1
fi
if [ ! -f "$CSV" ]; then
  echo "ERROR: CSV file not found: $CSV" >&2
  exit 1
fi
if [ ! -r "$CSV" ]; then
  echo "ERROR: CSV file not readable: $CSV" >&2
  exit 1
fi

# Output folder: explicit arg, else derive a /scans sibling of a /wireless dir,
# else fall back to the CSV's own directory.
if [ -n "${2:-}" ]; then
  OUT="$2"
else
  CSVDIR="$(dirname "$CSV")"
  case "$CSVDIR" in
    */wireless) OUT="${CSVDIR%/wireless}/scans" ;;
    *)          OUT="$CSVDIR" ;;
  esac
fi
OUT="${OUT%/}"   # normalize: strip any trailing slash
mkdir -p "$OUT" || { echo "ERROR: cannot create output folder: $OUT" >&2; exit 1; }

REPORT="$OUT/flagged_report.txt"
MACLIST="$OUT/flagged_macs.txt"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED=$'\033[1;31m'
ORANGE=$'\033[38;5;208m'
YELLOW=$'\033[1;93m'
CYAN=$'\033[1;36m'
GREEN=$'\033[1;32m'
DIM=$'\033[2m'
NC=$'\033[0m'

# ---------------------------------------------------------------------------
# Known surveillance OUI prefixes (lowercase, xx:xx:xx) -> vendor  [RED]
# ---------------------------------------------------------------------------
declare -A OUI_RED=(
  [b0:09:da]="Ring"      [78:8a:20]="Ring"
  [6c:56:97]="Arlo"      [44:65:0d]="Arlo"      [3e:9c:b5]="Arlo"
  [2c:aa:8e]="Wyze"      [d0:3f:27]="Wyze"
  [f4:f2:28]="Blink"     [44:a6:e5]="Blink"
  [d4:52:bf]="Eufy"      [84:c9:b2]="Eufy"
  [9c:8e:cd]="Amcrest"   [00:49:c1]="Amcrest"
  [ec:71:db]="Reolink"   [b0:c5:54]="Reolink"
  [4c:11:bf]="Hikvision" [bc:ad:28]="Hikvision" [c4:2f:90]="Hikvision"
  [90:02:a9]="Dahua"     [e0:50:8b]="Dahua"
  [18:b4:30]="Nest"      [64:16:66]="Nest"
)

# High-priority DIY covert device OUIs (lowercase) -> vendor  [ORANGE]
declare -A OUI_ORANGE=(
  [dc:4f:22]="Espressif" [e8:db:84]="Espressif" [cc:50:e3]="Espressif" [24:0a:c4]="Espressif"
  [b8:27:eb]="RaspberryPi" [dc:a6:32]="RaspberryPi" [e4:5f:01]="RaspberryPi"
)

# SSID keyword lists
CAM_KW=(arlo ring wyze blink eufy hikvision dahua amcrest reolink foscam nest axis camera cam cctv ipcam nvr dvr)
COVERT_KW=(setup iot hidden spy wifi-cam ipcamera smartcam vsee zmodo)

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
RED_COUNT=0
ORANGE_COUNT=0
YELLOW_COUNT=0

# Temp file to accumulate flagged MACs for this run (deduped into MACLIST later)
TMPMAC="$(mktemp)"
trap 'rm -f "$TMPMAC"' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"   # leading whitespace
  s="${s%"${s##*[![:space:]]}"}"   # trailing whitespace
  printf '%s' "$s"
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Column format (no trailing newline — added per output stream)
FMT="%-8s %-17s %-28s %7s %4s %-9s %s"

# emit <color> <flag> <mac> <ssid> <signal> <chan> <enc> <reason>
emit() {
  local color="$1" flag="$2" mac="$3" ssid="$4" sig="$5" ch="$6" enc="$7" reason="$8"
  local disp_ssid="$ssid"
  [ -z "$disp_ssid" ] && disp_ssid="<hidden>"
  local row
  row="$(printf "$FMT" "$flag" "$mac" "$disp_ssid" "$sig" "$ch" "$enc" "$reason")"
  printf '%b%s%b\n' "$color" "$row" "$NC"     # colored -> stdout
  printf '%s\n' "$row" >> "$REPORT"           # plain   -> report file
  printf '%s\n' "$mac" >> "$TMPMAC"           # collect MAC
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
TS="$(date '+%Y-%m-%d %H:%M:%S %Z')"

: > "$REPORT"   # truncate report for this run
{
  printf '%s\n' "==================================================================="
  printf '%s\n' " DSG TSCM TRIAGE — AUTO-FLAG CAPTURE ANALYSIS"
  printf '%s\n' " Surveillance Specialist Group, LLC"
  printf '%s\n' "==================================================================="
  printf ' Timestamp : %s\n' "$TS"
  printf ' Case path : %s\n' "$OUT"
  printf ' CSV file  : %s\n' "$CSV"
  printf '%s\n' "-------------------------------------------------------------------"
  printf "$FMT\n" "FLAG" "MAC" "SSID" "SIGNAL" "CH" "ENCRYPT" "REASON"
  printf '%s\n' "-------------------------------------------------------------------"
} | tee -a "$REPORT"

# ---------------------------------------------------------------------------
# Parse CSV — two sections: Access Points, then Stations (clients)
# airodump CSVs use CRLF line endings; strip the trailing CR.
# ---------------------------------------------------------------------------
section=""
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"                       # strip CR
  [ -z "$(trim "$line")" ] && continue       # skip blank lines

  case "$line" in
    BSSID,*|"BSSID ,"*)      section="ap";      continue ;;
    "Station MAC,"*|"Station MAC ,"*) section="station"; continue ;;
  esac
  [ -z "$section" ] && continue

  # Split into fields
  IFS=',' read -r -a F <<< "$line"

  if [ "$section" = "ap" ]; then
    mac="$(lower "$(trim "${F[0]:-}")")"
    ch="$(trim "${F[3]:-}")"
    enc="$(trim "${F[5]:-}")"
    sig="$(trim "${F[8]:-}")"
    ssid="$(trim "${F[13]:-}")"
  else
    mac="$(lower "$(trim "${F[0]:-}")")"
    ch="-"
    enc="-"
    sig="$(trim "${F[3]:-}")"
    # Probed ESSIDs span field 6..end (they are themselves comma-separated)
    ssid=""
    if [ "${#F[@]}" -gt 6 ]; then
      probed=""
      for ((i=6; i<${#F[@]}; i++)); do
        p="$(trim "${F[$i]}")"
        [ -z "$p" ] && continue
        probed="${probed:+$probed,}$p"
      done
      ssid="$probed"
    fi
  fi

  # Skip rows without a plausible MAC
  case "$mac" in
    [0-9a-f][0-9a-f]:*) ;;   # looks like a MAC
    *) continue ;;
  esac

  oui="${mac:0:8}"
  lssid="$(lower "$ssid")"

  # --- Determine flag level (priority RED > ORANGE > YELLOW) ---
  flag=""; color=""; reason=""

  # RED: known surveillance OUI
  if [ -n "${OUI_RED[$oui]:-}" ]; then
    flag="RED"; color="$RED"; reason="OUI=${OUI_RED[$oui]}"
  fi

  # RED: camera SSID keyword
  if [ -z "$flag" ] && [ -n "$lssid" ]; then
    for kw in "${CAM_KW[@]}"; do
      if [[ "$lssid" == *"$kw"* ]]; then
        flag="RED"; color="$RED"; reason="SSID~'$kw'"; break
      fi
    done
  fi

  # ORANGE: DIY covert OUI
  if [ -z "$flag" ] && [ -n "${OUI_ORANGE[$oui]:-}" ]; then
    flag="ORANGE"; color="$ORANGE"; reason="OUI=${OUI_ORANGE[$oui]} (DIY)"
  fi

  # YELLOW: covert/setup SSID keyword
  if [ -z "$flag" ] && [ -n "$lssid" ]; then
    for kw in "${COVERT_KW[@]}"; do
      if [[ "$lssid" == *"$kw"* ]]; then
        flag="YELLOW"; color="$YELLOW"; reason="SSID~'$kw'"; break
      fi
    done
  fi

  # YELLOW: hidden network (empty ESSID, or literal length:0)
  if [ -z "$flag" ] && [ "$section" = "ap" ]; then
    if [ -z "$ssid" ] || [[ "$lssid" == *"length: 0"* ]] || [[ "$lssid" == *"length:0"* ]]; then
      flag="YELLOW"; color="$YELLOW"; reason="hidden SSID"
    fi
  fi

  [ -z "$flag" ] && continue   # not flagged

  case "$flag" in
    RED)    RED_COUNT=$((RED_COUNT+1)) ;;
    ORANGE) ORANGE_COUNT=$((ORANGE_COUNT+1)) ;;
    YELLOW) YELLOW_COUNT=$((YELLOW_COUNT+1)) ;;
  esac

  emit "$color" "$flag" "$mac" "$ssid" "$sig" "$ch" "$enc" "$reason"
done < "$CSV"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((RED_COUNT+ORANGE_COUNT+YELLOW_COUNT))
{
  printf '%s\n' "-------------------------------------------------------------------"
} | tee -a "$REPORT"

printf '%b SUMMARY:%b %b%d RED%b (confirmed surveillance)  %b%d ORANGE%b (DIY covert)  %b%d YELLOW%b (suspicious)\n' \
  "$CYAN" "$NC" "$RED" "$RED_COUNT" "$NC" "$ORANGE" "$ORANGE_COUNT" "$NC" "$YELLOW" "$YELLOW_COUNT" "$NC"
printf ' SUMMARY: %d RED flags, %d ORANGE flags, %d YELLOW flags (%d total)\n' \
  "$RED_COUNT" "$ORANGE_COUNT" "$YELLOW_COUNT" "$TOTAL" >> "$REPORT"

# ---------------------------------------------------------------------------
# Flagged MAC list (append + dedupe for use in other commands)
# ---------------------------------------------------------------------------
if [ -s "$TMPMAC" ]; then
  touch "$MACLIST"
  cat "$TMPMAC" >> "$MACLIST"
  sort -u -o "$MACLIST" "$MACLIST"
fi

printf '%b\n' "${DIM} Report saved : $REPORT${NC}"
printf '%b\n' "${DIM} Flagged MACs : $MACLIST${NC}"

if [ "$TOTAL" -eq 0 ]; then
  printf '%b\n' "${GREEN} No flagged devices in this capture.${NC}"
fi

exit 0
