# DSG TSCM Triage

A web-based TSCM (Technical Surveillance Countermeasures) network intelligence platform built for licensed private investigators and security professionals. Developed by Surveillance Specialist Group, LLC d/b/a Data Specialist Group.

DSG TSCM Triage provides a single, guided console for sweeping a client environment for covert network-connected surveillance devices — hidden cameras, wireless bugs, rogue access points, and other unauthorized devices — and for capturing court-ready evidence to a structured case folder.

## Features

Each mode panel delivers a guided, copy-and-run workflow with commands pre-tokenized for the selected interface, subnet, and case folder:

| Panel | Purpose |
|-------|---------|
| **Host Scan** | Discover live hosts on the local subnet (arp-scan, nmap ping sweep, netdiscover) |
| **Port Scan** | Surveillance-port sweeps plus single-host full-port scans |
| **OUI Check** | Identify device vendors from MAC address OUI prefixes |
| **ONVIF** | Detect ONVIF/UPnP IP cameras via WS-Discovery and SSDP |
| **Traffic Analysis** | Live packet and connection analysis with tshark |
| **WiFi** | 802.11 survey and capture, including hidden SSIDs (airodump-ng, kismet), with a passive-RF enumeration explainer and capture-timing guidance |
| **Bluetooth** | Classic Bluetooth and BLE enumeration for covert audio bugs |
| **Deauth Discovery** | Post-router-down device detection — surface covert devices that fall back to their own setup AP |
| **Network Cam** | Locate networked cameras by vendor MAC and RTSP/HTTP fingerprint |
| **Hidden Cam** | Hunt for concealed cameras via RTSP stream discovery and brute |
| **Network KVM** | Detect KVM-over-IP devices (keyboard/video/mouse switches with network access) — a significant covert remote-access risk — by vendor OUI and management-port fingerprint |
| **DNS Leak** | Passive DNS query monitoring and leak detection |
| **Shodan** | External exposure and device intelligence via Shodan |
| **Threat Intel** | Reputation and threat lookups for observed hosts |
| **Email OSINT** | Open-source intelligence on email addresses |
| **Phone OSINT** | Open-source intelligence on phone numbers |
| **Username** | Cross-platform username enumeration |
| **Breach Data** | Credential and breach exposure checks |
| **PCAP Analysis** | Capture and analyze evidentiary packet captures |
| **Eyewitness** | Automated screenshotting of discovered web services |
| **Report Generation** | Produce timestamped TXT/PDF case reports |

A **Hacker Hunting** section adds counter-intrusion tooling: the **HACK HW** panel cross-references known pentest/covert-hardware OUIs (Raspberry Pi, Espressif ESP, Alfa, GL.iNet, Hak5 Pineapple, Arduino, FlipperZero), detects WiFi Pineapple management interfaces and default gateways, runs BLE scans for FlipperZero-class tools, and diffs pre/post-deauth captures for rogue APs and evil twins.

An **Enterprise (ENT)** section adds advanced panels for larger engagements: ARP Watch, Rogue DHCP, Device Delta, mDNS/SSDP, Cert Scan, MAC Randomization, Covert Channel, Bandwidth, Timeline, and Case Summary.

## Requirements

- Kali Linux (recommended) or any Debian-based Linux
- Python 3.x
- Flask (`pip install flask flask-cors wsdiscovery`)
- Chromium or Firefox

Most scan panels rely on standard TSCM/network tooling (nmap, arp-scan, aircrack-ng suite, tshark/wireshark, netdiscover, kismet, eyewitness, hackrf/rtl-sdr, docker). The installer provisions all of these in one pass, configures tshark capture permissions (wireshark group), and installs optional OSINT tools (holehe, phoneinfoga, sherlock) where available.

## Installation

```bash
git clone https://github.com/DSGTampa/TSCM-Triage.git
cd TSCM-Triage
chmod +x install_dsg_tscm.sh
bash install_dsg_tscm.sh
```

## Launch

- **Without Flask server:** `bash launch.sh`
- **With Flask server (enables live interface detection):** `bash launch_server.sh`

The application opens at `http://127.0.0.1:5555` in Chromium (app mode) or Firefox. With the Flask server running, the **↺ SCAN** button auto-detects available network interfaces and subnets.

### Redirecting case output to an external drive

Case output defaults to `~/DSG-TSCM/cases`. To write it to an external drive instead — recommended on Raspberry Pi deployments to spare the SD card from scan/capture write wear — pass `--cases-path`:

```bash
bash launch_server.sh --cases-path /media/usb/DSG-TSCM/cases
```

When a non-default path is active, the interface shows an amber **Cases → …** notice so the examiner always knows where evidence is being written, and every `{CASE_PATH}` token resolves to that location.

## Updating

New releases are published to this repository. To pull the latest changes onto your machine and redeploy them to the runtime location (`~/dsg-tscm`):

**Option A — one command (recommended):**

```bash
cd TSCM-Triage        # the folder you cloned into
git pull
bash update.sh        # copies updated files to ~/dsg-tscm and restarts the server if running
```

**Option B — manual:**

```bash
cd TSCM-Triage
git pull                                      # fetch the latest code
cp dsg_tscm_triage.html ~/dsg-tscm/           # deploy the updated UI
cp server.py ~/dsg-tscm/                       # deploy the updated Flask server
pkill -f "python3 server.py" 2>/dev/null       # stop the running server (if any)
bash ~/dsg-tscm/launch_server.sh               # relaunch with the new version
```

After updating, hard-refresh the browser (**Ctrl+Shift+R**) so the new UI loads instead of a cached copy. You can confirm the running version in the badge at the top of the page and in the footer (currently **v1.8.3**).

> **Tip:** run `git log --oneline -5` after pulling to see what changed in the latest releases.

## Changelog

### v1.8.3 (current)

- **New — Network KVM panel** (Cameras): detects KVM-over-IP devices by vendor OUI (Aten, Raritan, Avocent, Belkin, Lantronix, Adder, Black Box, Rose) and scans KVM/VNC management ports, with a collapsible OUI reference and covert-access-risk guidance.
- **New — Hacker Hunting section** with the **HACK HW** panel: pentest/covert-hardware OUI cross-reference, WiFi Pineapple detection (port 1471, SSID grep, default gateway), BLE FlipperZero scan, and rogue-AP/evil-twin detection via pre/post-deauth diff. Capture-dependent commands are guarded so a missing capture prints clear guidance instead of failing silently.
- **New — WiFi passive-RF enumeration explainer**: a collapsible banner explaining monitor-mode passive capture with minimum/recommended capture-timing warnings.
- **New — external-drive case output**: `launch_server.sh --cases-path <dir>` redirects all case output (Raspberry Pi SD-card protection), surfaced in the UI via an amber notice and the `/api/config` endpoint.
- **Fix — arp-scan OUI/vendor resolution**: all arp-scan commands now pass explicit `--ouifile` / `--macfile`; the installer symlinks `mac-vendor.txt` to `ieee-oui.txt` for builds that ship only the OUI file. The brittle OUI `chmod` preflight and `--download-vendors` steps were removed.
- **Fix — Kismet log path**: corrected a double-slash in `--log-prefix` and pre-create the log directory.
- **UI — OSINT section** (Email, Phone, Username, Breach) moved to the bottom of the mode list.
- **Installer** now provisions the full dependency set in one pass and configures tshark capture permissions.

### v1.8.2

- Live interface detection and local API via the Flask server; functional **[▶] run** button (`/api/run`); simplified interface selector; Enterprise (ENT) section.

## Legal

For use by licensed professionals only. FL PI License A3200144. Surveillance Specialist Group, LLC. [dataspecialistgroup.com](https://dataspecialistgroup.com)

All scanning and surveillance-countermeasure activity must be conducted only on networks and premises you are authorized to assess.
