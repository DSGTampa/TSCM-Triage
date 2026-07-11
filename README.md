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
| **WiFi** | 802.11 survey and capture, including hidden SSIDs (airodump-ng, kismet) |
| **Bluetooth** | Classic Bluetooth and BLE enumeration for covert audio bugs |
| **Deauth Discovery** | Post-router-down device detection — surface covert devices that fall back to their own setup AP |
| **Network Cam** | Locate networked cameras by vendor MAC and RTSP/HTTP fingerprint |
| **Hidden Cam** | Hunt for concealed cameras via RTSP stream discovery and brute |
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

An **Enterprise (ENT)** section adds advanced panels for larger engagements: ARP Watch, Rogue DHCP, Device Delta, mDNS/SSDP, Cert Scan, MAC Randomization, Covert Channel, Bandwidth, Timeline, and Case Summary.

## Requirements

- Kali Linux (recommended) or any Debian-based Linux
- Python 3.x
- Flask (`pip install flask flask-cors`)
- Chromium or Firefox

Most scan panels rely on standard TSCM/network tooling (nmap, arp-scan, aircrack-ng suite, tshark/wireshark, netdiscover). The installer provisions these dependencies.

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

After updating, hard-refresh the browser (**Ctrl+Shift+R**) so the new UI loads instead of a cached copy. You can confirm the running version in the badge at the top of the page and in the footer (currently **v1.8.2**).

> **Tip:** run `git log --oneline -5` after pulling to see what changed in the latest releases.

## Legal

For use by licensed professionals only. FL PI License A3200144. Surveillance Specialist Group, LLC. [dataspecialistgroup.com](https://dataspecialistgroup.com)

All scanning and surveillance-countermeasure activity must be conducted only on networks and premises you are authorized to assess.
