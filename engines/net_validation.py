"""
net_validation.py — NETWORK VALIDATION two-step counter-surveillance workflow.

Ported into DSG TSCM Triage from DSG Sentinel.

Step 1: enumerate Wi-Fi access points so the examiner can mark which ones belong
to the client's own network. Step 2: list the client devices associated with the
selected APs so each can be physically located and marked VERIFIED or UNRESOLVED.

Association is read straight from the Kismet BLOB: each AP carries the MAC list of
its associated clients, and each client carries the BSSID it last joined.

Checklist state (selected APs + per-device status/notes) persists to
data/validation_session.json so the examiner can close the browser and resume.
"""

import html
import json
import os
import threading
import time

# status tokens + their human labels
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_VERIFIED = "VERIFIED"
STATUS_UNRESOLVED = "UNRESOLVED"
STATUS_LABELS = {
    STATUS_UNVERIFIED: "UNVERIFIED",
    STATUS_VERIFIED: "VERIFIED — LOCATED",
    STATUS_UNRESOLVED: "UNRESOLVED — NOT FOUND",
}

_VENDOR_TYPE = [
    ("apple", "Apple device (iPhone / iPad / Mac / Watch)"),
    ("samsung", "Samsung device (phone / tablet / TV)"),
    ("google", "Google / Android device"),
    ("amazon", "Amazon device (Echo / Fire / IoT)"),
    ("intel", "Laptop (Intel Wi-Fi)"),
    ("microsoft", "Microsoft device (Surface / Xbox)"),
    ("espressif", "IoT / ESP microcontroller"),
    ("raspberr", "Raspberry Pi / single-board computer"),
    ("cisco", "Network / infrastructure device"),
    ("tp-link", "Router / network device"),
    ("netgear", "Router / network device"),
    ("ubiquiti", "Router / network device"),
]


def _norm(mac):
    return (mac or "").strip().upper()


def _device_type(vendor):
    v = (vendor or "").lower()
    for needle, label in _VENDOR_TYPE:
        if needle in v:
            return label
    return "Wi-Fi client device"


def list_aps(db):
    """All Wi-Fi access points, richest (most clients / strongest) first."""
    if db is None:
        return []
    aps = db.get_all_devices(since_epoch=0, category="wifi_ap", limit=5000)
    out = [{
        "mac": a["mac"],
        "ssid": a.get("ssid") or "",
        "vendor": a.get("vendor") or "Unknown",
        "channel": a.get("channel") or "",
        "rssi": a.get("rssi"),
        "client_count": a.get("client_count") or 0,
    } for a in aps]
    out.sort(key=lambda x: (-(x["client_count"] or 0), -(x["rssi"] or -999)))
    return out


def list_clients(db, ap_macs):
    """Client devices associated with any of the selected APs."""
    if db is None:
        return []
    ap_set = {_norm(m) for m in (ap_macs or []) if m}
    if not ap_set:
        return []
    # The AP-side association map is authoritative — it lists the clients each AP
    # actually served. last_bssid matching is broader, so we only fall back to it
    # for APs that expose no association map.
    linked = set()
    for a in db.get_all_devices(since_epoch=0, category="wifi_ap", limit=5000):
        if _norm(a["mac"]) in ap_set:
            linked.update(a.get("client_macs", []))

    out, seen = [], set()
    for c in db.get_all_devices(since_epoch=0, category="wifi_client", limit=30000):
        mac = _norm(c["mac"])
        if mac in seen:
            continue
        match = (mac in linked) if linked else (c.get("last_bssid") in ap_set)
        if match:
            seen.add(mac)
            out.append({
                "mac": c["mac"],
                "vendor": c.get("vendor") or "Unknown",
                "device_type": _device_type(c.get("vendor")),
                "rssi": c.get("rssi"),
                "first_seen": c.get("first_seen"),
                "last_seen": c.get("last_seen"),
                "bssid": c.get("last_bssid") or "",
            })
    out.sort(key=lambda x: (x["vendor"], x["mac"]))
    return out


class ValidationSession:
    """Persisted checklist: selected APs + per-device {status, notes}."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def load(self):
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("selected_aps", [])
                data.setdefault("clients", {})
                data.setdefault("updated_ts", None)
                return data
        except (OSError, ValueError):
            pass
        return {"selected_aps": [], "clients": {}, "updated_ts": None}

    def _write(self, out):
        with self._lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(out, f, indent=2)
            os.replace(tmp, self.path)
        return out

    def save(self, data):
        """Replace the whole session (selected APs + all client records)."""
        out = {
            "selected_aps": [_norm(m) for m in data.get("selected_aps", [])],
            "clients": {},
            "updated_ts": int(time.time()),
        }
        for mac, rec in (data.get("clients") or {}).items():
            out["clients"][_norm(mac)] = _clean_rec(rec)
        return self._write(out)

    def set_aps(self, ap_macs):
        data = self.load()
        data["selected_aps"] = [_norm(m) for m in (ap_macs or [])]
        data["updated_ts"] = int(time.time())
        return self._write(data)

    def set_client(self, mac, status=None, notes=None):
        """Update a single client's status and/or notes, preserving the rest."""
        data = self.load()
        clients = dict(data.get("clients", {}))
        rec = dict(clients.get(_norm(mac), {"status": STATUS_UNVERIFIED, "notes": ""}))
        if status is not None:
            rec["status"] = status if status in STATUS_LABELS else STATUS_UNVERIFIED
        if notes is not None:
            rec["notes"] = str(notes)[:500]
        clients[_norm(mac)] = _clean_rec(rec)
        data["clients"] = clients
        data["updated_ts"] = int(time.time())
        return self._write(data)


def _clean_rec(rec):
    rec = rec or {}
    status = rec.get("status", STATUS_UNVERIFIED)
    if status not in STATUS_LABELS:
        status = STATUS_UNVERIFIED
    return {"status": status, "notes": (rec.get("notes") or "")[:500]}


# ── report ────────────────────────────────────────────────────────────────
def _e(s):
    return html.escape(str(s if s is not None else ""))


def _dt(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else "—"


def _t(epoch):
    return time.strftime("%H:%M:%S", time.localtime(epoch)) if epoch else "—"


_REPORT_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; padding:28px; background:#070c14; color:#b8d4e8;
  font-family:'Share Tech Mono','Courier New',monospace; font-size:14px; }
h1 { font-size:22px; letter-spacing:3px; color:#00c8d7; margin:0 0 4px; }
h2 { font-size:15px; letter-spacing:2px; color:#00c8d7; margin:22px 0 8px; }
.meta { color:#4a6e8a; font-size:12px; line-height:1.6; margin-bottom:6px; }
.meta b { color:#b8d4e8; font-weight:normal; }
table { width:100%; border-collapse:collapse; margin-top:8px; font-size:12px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid #0e1822; vertical-align:top; }
th { color:#4a6e8a; font-weight:normal; letter-spacing:1px; }
td.mac { color:#00c8d7; }
tr.ap { background:rgba(61,220,132,0.05); }
.st-verified { color:#00aaff; }
.st-unresolved { color:#ff6b6b; }
.st-unverified { color:#f0a832; }
.summary { border:1px solid #162536; border-left:4px solid #00c8d7; border-radius:8px;
  padding:10px 14px; margin:14px 0; color:#b8d4e8; }
.note { color:#dff3e6; }
.explain { border:1px solid #162536; border-left:4px solid #f0a832; border-radius:8px;
  padding:12px 14px; margin:16px 0; color:#b8d4e8; font-size:13px; line-height:1.6; }
.sign { margin-top:26px; border-top:1px solid #2e5070; padding-top:14px; color:#b8d4e8; font-size:13px; }
.sign .line { display:inline-block; border-bottom:1px solid #4a6e8a; min-width:280px; margin-left:8px; }
.enrolled { color:#00aaff; margin-top:14px; font-size:13px; }
.footer { margin-top:24px; color:#4a7a4a; font-size:11px; letter-spacing:1px; text-align:center; }
@page { margin:14mm; }
@media print {
  body { background:#fff; color:#000; padding:0; font-size:10.5pt; }
  h1,h2 { color:#000; }
  .meta,.meta b,td,th,.summary,.explain,.note,.sign,.enrolled,.footer { color:#000; }
  .summary,.explain { background:#fff; border-color:#000; border-left:4px solid #000; page-break-inside:avoid; }
  table,tr { page-break-inside:avoid; }
  td.mac { color:#000; } tr.ap { background:#f2f2f2; }
  .st-verified { color:#000; font-weight:bold; }
  .st-unresolved { color:#000; font-weight:bold; text-decoration:underline; }
  .st-unverified { color:#000; }
  th { border-bottom:1px solid #000; } td { border-bottom:1px solid #999; }
  .sign .line { border-bottom:1px solid #000; }
}
""".strip()

_SHIELD = "\U0001F6E1"  # 🛡 — marks a VERIFIED (physically located) device


def _status_class(status):
    return {"VERIFIED": "st-verified", "UNRESOLVED": "st-unresolved"}.get(
        status, "st-unverified")


def _status_text(status):
    label = STATUS_LABELS.get(status, status)
    return (_SHIELD + " " + label) if status == STATUS_VERIFIED else label


def render_validation_report(aps, clients, session, meta=None):
    """Return a self-contained, printable HTML Network Validation report."""
    meta = meta or {}
    session = session or {}
    cmap = session.get("clients", {})

    ap_rows = "".join(
        "<tr class=\"ap\"><td class=\"mac\">{mac}</td><td>{ssid}</td><td>{vendor}</td>"
        "<td>{ch}</td><td>{sig}</td><td>{cc}</td></tr>".format(
            mac=_e(a["mac"]), ssid=_e(a.get("ssid") or "(hidden)"),
            vendor=_e(a.get("vendor")), ch=_e(a.get("channel")),
            sig=(str(a["rssi"]) + " dBm") if a.get("rssi") else "—",
            cc=a.get("client_count", 0))
        for a in aps) or '<tr><td colspan="6">No APs selected.</td></tr>'

    verified = unresolved = 0
    cli_rows = []
    for c in clients:
        rec = cmap.get(_norm(c["mac"]), {})
        status = rec.get("status", STATUS_UNVERIFIED)
        if status == STATUS_VERIFIED:
            verified += 1
        elif status == STATUS_UNRESOLVED:
            unresolved += 1
        cli_rows.append(
            "<tr><td class=\"mac\">{mac}</td><td>{vendor}</td><td>{typ}</td>"
            "<td>{sig}</td><td>{first}</td><td>{last}</td>"
            "<td class=\"{sc}\">{status}</td><td class=\"note\">{notes}</td></tr>".format(
                mac=_e(c["mac"]), vendor=_e(c.get("vendor")),
                typ=_e(c.get("device_type")),
                sig=(str(c["rssi"]) + " dBm") if c.get("rssi") else "—",
                first=_t(c.get("first_seen")), last=_t(c.get("last_seen")),
                sc=_status_class(status), status=_e(_status_text(status)),
                notes=_e(rec.get("notes") or "")))
    cli_html = "".join(cli_rows) or '<tr><td colspan="8">No client devices.</td></tr>'

    total = len(clients)
    explain = (
        '<div class="explain"><b>What "unresolved" devices mean.</b> An unresolved '
        "device is a client that was seen associated with the client's own network but "
        "could <u>not</u> be physically located and accounted for by the examiner during "
        "the sweep. Unresolved devices require follow-up: they may be a legitimate device "
        "that was simply out of reach (in a drawer, a neighbouring unit, a vehicle), or "
        "they may be an unauthorised device that should be investigated as a potential "
        "surveillance or data-exfiltration risk. Every unresolved entry should be run down "
        "until it is either located and reclassified, or confirmed removed. Devices marked "
        + _SHIELD + " <b>VERIFIED</b> were physically located by the examiner and enrolled "
        "as known/authorized.</div>")

    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>DSG TSCM Triage — Network Validation Sweep</title>"
        "<style>{css}</style></head><body>"
        "<h1>NETWORK VALIDATION SWEEP</h1>"
        '<div class="meta"><b>Surveillance Specialist Group, LLC</b> · DSG TSCM Triage · '
        "Counter-Surveillance Network Validation</div>"
        '<div class="meta">dataspecialistgroup.com &nbsp;·&nbsp; (877) 787-7075 &nbsp;·&nbsp; '
        "FL PI LICENSE A3200144</div>"
        '<div class="meta"><b>Sweep date/time:</b> {when}</div>'
        '<div class="meta"><b>Capture:</b> {capture}</div>'
        "<h2>SELECTED ACCESS POINTS ({nap})</h2>"
        "<table><thead><tr><th>BSSID (MAC)</th><th>SSID</th><th>VENDOR</th>"
        "<th>CH</th><th>SIGNAL</th><th>CLIENTS</th></tr></thead><tbody>{aps}</tbody></table>"
        "<h2>CLIENT DEVICES ({total})</h2>"
        "<table><thead><tr><th>MAC</th><th>VENDOR</th><th>OUI DEVICE TYPE</th>"
        "<th>SIGNAL</th><th>FIRST</th><th>LAST</th><th>STATUS</th><th>EXAMINER NOTES</th>"
        "</tr></thead><tbody>{clients}</tbody></table>"
        '<div class="summary"><b>{total}</b> devices found &nbsp;·&nbsp; '
        '<span class="st-verified"><b>{verified}</b> verified (located)</span> '
        '&nbsp;·&nbsp; <span class="st-unresolved"><b>{unresolved}</b> unresolved '
        "(not found)</span></div>"
        "{explain}"
        '<div class="enrolled">' + _SHIELD + ' All verified devices were enrolled into the '
        "DSG TSCM Triage baseline as authorized/known devices.</div>"
        '<div class="sign"><b>Examining TSCM professional:</b>'
        '<br><br>Signature: <span class="line"></span> &nbsp;&nbsp; Date: '
        '<span class="line" style="min-width:160px"></span>'
        '<br><br>Printed name: <span class="line"></span></div>'
        '<div class="footer">Generated by DSG TSCM Triage · Surveillance Specialist Group, '
        "LLC · Network Validation</div>"
        "</body></html>"
    ).format(
        css=_REPORT_CSS, when=_dt(meta.get("generated_ts") or int(time.time())),
        capture=_e(meta.get("capture") or "—"),
        nap=len(aps), aps=ap_rows, total=total, clients=cli_html,
        verified=verified, unresolved=unresolved, explain=explain)
