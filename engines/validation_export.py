"""
validation_export.py — multi-format export for the Network Validation sweep.

Builds one canonical report model from the Kismet capture + the examiner's saved
validation session + the enrolled baseline, then renders it to TXT, CSV, a dark
self-contained HTML page, and a print-friendly PDF (WeasyPrint, falling back to
wkhtmltopdf). Every format carries the same SHA256 of the report content so a
signed copy can be verified later.

Statuses come from the examiner checklist (VERIFIED / UNRESOLVED / UNVERIFIED).
Findings are flagged three ways: UNRESOLVED (advisory / amber), NOT IN BASELINE
(critical / red), and locally-administered MAC (critical / red).
"""

import csv
import hashlib
import html
import io
import json
import os
import subprocess
import tempfile
import time

from engines import net_validation

FL_PI_LICENSE = "A3200144"
PHONE = "(877) 787-7075"
SITE = "dataspecialistgroup.com"


# ── helpers ─────────────────────────────────────────────────────────────────
def _n(mac):
    return (mac or "").strip().upper()


def _e(s):
    return html.escape(str(s if s is not None else ""))


def _dt(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else "—"


def _is_laa(mac):
    """True if the MAC is locally administered (bit 1 of the first octet set)."""
    try:
        return bool(int(_n(mac).replace(":", "")[0:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


# ── model ───────────────────────────────────────────────────────────────────
def build_model(db, session, baseline, case="", examiner="",
                capture=None, generated_ts=None):
    """Assemble the canonical report model (dict) used by every renderer."""
    session = session or {}
    cmap = {_n(m): (r or {}) for m, r in (session.get("clients") or {}).items()}
    selected = {_n(m) for m in (session.get("selected_aps") or [])}

    ap_rows = []
    for a in net_validation.list_aps(db):
        verified = _n(a["mac"]) in selected
        ap_rows.append({
            "ssid": a.get("ssid") or "",
            "bssid": a["mac"],
            "channel": a.get("channel") or "",
            "signal": (str(a["rssi"]) + " dBm") if a.get("rssi") is not None else "—",
            "status": "VERIFIED" if verified else "UNRESOLVED",
        })

    base_set = {_n(m) for m in (baseline or {}).keys()}
    dev_rows, unresolved, not_found, laa = [], [], [], []
    verified_ct = 0
    for c in net_validation.list_clients(db, list(selected)):
        mac = _n(c["mac"])
        status = cmap.get(mac, {}).get("status", "UNVERIFIED")
        in_base = mac in base_set
        is_laa = _is_laa(mac)
        if status == "VERIFIED":
            verified_ct += 1
        row = {
            "ip": "—",  # passive Wi-Fi capture carries no L3 address
            "mac": c["mac"],
            "vendor": c.get("vendor") or "Unknown",
            "status": status,
            "first_seen": _dt(c.get("first_seen")),
            "last_seen": _dt(c.get("last_seen")),
            "in_baseline": in_base,
            "laa": is_laa,
        }
        dev_rows.append(row)
        if status == "UNRESOLVED":
            unresolved.append(row)
        if not in_base:
            not_found.append(row)
        if is_laa:
            laa.append(row)

    ts = generated_ts or int(time.time())
    model = {
        "case": case or "",
        "examiner": examiner or "",
        "generated_ts": ts,
        "date": time.strftime("%Y-%m-%d", time.localtime(ts)),
        "time": time.strftime("%H:%M:%S", time.localtime(ts)),
        "capture": capture,
        "aps": ap_rows,
        "devices": dev_rows,
        "summary": {
            "aps_observed": len(ap_rows),
            "verified": verified_ct,
            "unresolved": sum(1 for r in dev_rows if r["status"] == "UNRESOLVED"),
            "not_found": len(not_found),
            "devices_total": len(dev_rows),
        },
        "flagged": {"unresolved": unresolved, "not_found": not_found, "laa": laa},
    }
    model["hash"] = _hash(model)
    return model


def _hash(model):
    core = {k: v for k, v in model.items() if k != "hash"}
    blob = json.dumps(core, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ── TXT ─────────────────────────────────────────────────────────────────────
def render_txt(m):
    def s(v):
        return str(v if v is not None else "")
    L = ["=== DATA SPECIALIST GROUP ===",
         "=== SURVEILLANCE SPECIALIST GROUP, LLC ===",
         "=== TSCM NETWORK VALIDATION REPORT ===",
         "",
         "FL PI License : " + FL_PI_LICENSE,
         "Case          : " + (m["case"] or "—"),
         "Examiner      : " + (m["examiner"] or "—"),
         "Date          : " + m["date"],
         "Time          : " + m["time"]]
    if m.get("capture"):
        L.append("Capture       : " + m["capture"])
    su = m["summary"]
    L += ["",
          "--- NETWORK VALIDATION SUMMARY ---",
          "Total APs observed       : %d" % su["aps_observed"],
          "Total devices verified   : %d" % su["verified"],
          "Total devices unresolved : %d" % su["unresolved"],
          "Total devices not found  : %d" % su["not_found"],
          "",
          "AP LIST:",
          "%-22s | %-17s | %-4s | %-9s | %-10s" % ("SSID", "BSSID", "CH", "SIGNAL", "STATUS")]
    for a in m["aps"]:
        L.append("%-22s | %-17s | %-4s | %-9s | %-10s" % (
            (s(a["ssid"])[:22] or "(hidden)"), a["bssid"], s(a["channel"])[:4],
            a["signal"], a["status"]))
    if not m["aps"]:
        L.append("(none)")
    L += ["",
          "DEVICE LIST:",
          "%-15s | %-17s | %-20s | %-12s | %-19s | %-19s" % (
              "IP", "MAC", "VENDOR", "STATUS", "FIRST SEEN", "LAST SEEN")]
    for d in m["devices"]:
        L.append("%-15s | %-17s | %-20s | %-12s | %-19s | %-19s" % (
            d["ip"], d["mac"], s(d["vendor"])[:20], d["status"],
            d["first_seen"], d["last_seen"]))
    if not m["devices"]:
        L.append("(none)")
    fl = m["flagged"]
    L += ["", "--- FLAGGED FINDINGS ---",
          "[AMBER] Unresolved devices (%d):" % len(fl["unresolved"])]
    for d in fl["unresolved"]:
        L.append("  " + d["mac"] + "  " + s(d["vendor"]))
    L.append("[RED]   Devices not found in baseline (%d):" % len(fl["not_found"]))
    for d in fl["not_found"]:
        L.append("  " + d["mac"] + "  " + s(d["vendor"]))
    L.append("[RED]   Locally administered MACs (%d):" % len(fl["laa"]))
    for d in fl["laa"]:
        L.append("  " + d["mac"] + "  " + s(d["vendor"]))
    L += ["",
          "Generated: " + m["date"] + " " + m["time"],
          "SHA256: " + m["hash"],
          "",
          "DSG TSCM Triage · " + SITE + " · " + PHONE]
    return "\n".join(L) + "\n"


# ── CSV ─────────────────────────────────────────────────────────────────────
def render_csv(m):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["SSID", "BSSID", "Channel", "Signal", "Status"])
    for a in m["aps"]:
        w.writerow([a["ssid"], a["bssid"], a["channel"], a["signal"], a["status"]])
    w.writerow([])  # blank line separates the two sections
    w.writerow(["IP", "MAC", "Vendor", "Status", "FirstSeen", "LastSeen"])
    for d in m["devices"]:
        w.writerow([d["ip"], d["mac"], d["vendor"], d["status"],
                    d["first_seen"], d["last_seen"]])
    buf.write("\n# SHA256: " + m["hash"] + "\n")
    return buf.getvalue()


# ── shared table builders ───────────────────────────────────────────────────
def _ap_table(m, badge):
    rows = "".join(
        "<tr><td>{ssid}</td><td class=mac>{bssid}</td><td>{ch}</td>"
        "<td>{sig}</td><td>{st}</td></tr>".format(
            ssid=_e(a["ssid"] or "(hidden)"), bssid=_e(a["bssid"]),
            ch=_e(a["channel"] or "—"), sig=_e(a["signal"]),
            st=badge(a["status"]))
        for a in m["aps"]) or '<tr><td colspan=5>No access points observed.</td></tr>'
    return ("<table><thead><tr><th>SSID</th><th>BSSID</th><th>CH</th>"
            "<th>SIGNAL</th><th>STATUS</th></tr></thead><tbody>"
            + rows + "</tbody></table>")


def _dev_table(m, badge, flag_cls):
    out = []
    for d in m["devices"]:
        cls = flag_cls(d)
        out.append(
            "<tr class='{cls}'><td class=mac>{ip}</td><td class=mac>{mac}</td>"
            "<td>{vendor}</td><td>{st}</td><td>{first}</td><td>{last}</td></tr>".format(
                cls=cls, ip=_e(d["ip"]), mac=_e(d["mac"]), vendor=_e(d["vendor"]),
                st=badge(d["status"]), first=_e(d["first_seen"]), last=_e(d["last_seen"])))
    rows = "".join(out) or "<tr><td colspan=6>No client devices.</td></tr>"
    return ("<table><thead><tr><th>IP</th><th>MAC</th><th>VENDOR</th>"
            "<th>STATUS</th><th>FIRST SEEN</th><th>LAST SEEN</th></tr></thead><tbody>"
            + rows + "</tbody></table>")


def _flagged_list(items, label):
    if not items:
        return "<li class=none>None.</li>"
    return "".join("<li><span class=mac>{mac}</span> — {vendor}</li>".format(
        mac=_e(d["mac"]), vendor=_e(d["vendor"])) for d in items)


def _summary_cards(m):
    su = m["summary"]
    cards = [("APs OBSERVED", su["aps_observed"], "c"),
             ("VERIFIED", su["verified"], "v"),
             ("UNRESOLVED", su["unresolved"], "u"),
             ("NOT FOUND", su["not_found"], "r")]
    return "".join(
        "<div class='card {k}'><div class=n>{n}</div><div class=l>{l}</div></div>".format(
            k=k, n=n, l=l) for l, n, k in cards)


# ── HTML (dark, self-contained) ─────────────────────────────────────────────
_HTML_CSS = """
:root{--bg:#070c14;--panel:#0e1822;--cyan:#00c8d7;--green:#3ddc84;--blue:#00aaff;
--red:#ff6b6b;--amber:#f0a832;--dim:#2e5070;--body:#b8d4e8;--border:#162536;}
*{box-sizing:border-box;} body{margin:0;padding:26px;background:#040810;color:var(--body);
font-family:'Share Tech Mono','Courier New',monospace;font-size:13px;}
.wrap{max-width:1100px;margin:0 auto;background:var(--bg);border:1px solid #14263a;padding:26px 30px;}
h1{color:var(--green);font-size:20px;letter-spacing:3px;margin:0 0 2px;}
h2{color:var(--cyan);font-size:14px;letter-spacing:2px;margin:26px 0 8px;border-bottom:1px solid var(--border);padding-bottom:5px;}
.sub{color:var(--dim);font-size:11px;letter-spacing:.08em;line-height:1.7;}
.sub b{color:var(--body);font-weight:400;}
.meta{color:var(--dim);font-size:12px;line-height:1.7;margin-top:10px;}
.meta b{color:var(--green);font-weight:400;}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 4px;}
.card{flex:1;min-width:130px;border:1px solid var(--border);border-radius:8px;padding:12px 14px;background:var(--panel);}
.card .n{font-size:26px;color:var(--body);} .card .l{font-size:10px;letter-spacing:.12em;color:var(--dim);margin-top:3px;}
.card.v{border-left:4px solid var(--blue);} .card.v .n{color:var(--blue);}
.card.u{border-left:4px solid var(--amber);} .card.u .n{color:var(--amber);}
.card.r{border-left:4px solid var(--red);} .card.r .n{color:var(--red);}
.card.c{border-left:4px solid var(--cyan);} .card.c .n{color:var(--cyan);}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px;}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top;}
th{color:var(--dim);letter-spacing:1px;font-weight:400;}
td.mac{color:var(--cyan);white-space:nowrap;}
tr.flag-red td{background:rgba(255,107,107,.09);} tr.flag-red td.mac{color:var(--red);}
tr.flag-amber td{background:rgba(240,168,50,.08);}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10.5px;letter-spacing:.06em;}
.b-verified{color:var(--blue);border:1px solid #00aaff55;background:#00aaff12;}
.b-unresolved{color:var(--red);border:1px solid #ff6b6b55;background:#ff6b6b12;}
.b-unverified{color:var(--amber);border:1px solid #f0a83255;background:#f0a83212;}
.findings{display:flex;flex-direction:column;gap:14px;}
.fbox{border:1px solid var(--border);border-radius:8px;padding:12px 16px;background:var(--panel);}
.fbox.amber{border-left:4px solid var(--amber);} .fbox.red{border-left:4px solid var(--red);}
.fbox h3{margin:0 0 8px;font-size:12px;letter-spacing:1px;}
.fbox.amber h3{color:var(--amber);} .fbox.red h3{color:var(--red);}
.fbox ul{margin:0;padding-left:18px;} .fbox li{margin:3px 0;} .fbox li.none{color:var(--dim);list-style:none;margin-left:-18px;}
.foot{margin-top:26px;border-top:1px solid var(--dim);padding-top:12px;color:var(--dim);font-size:11px;line-height:1.7;}
.foot .hash{color:var(--green);word-break:break-all;}
@media print{body{background:#fff;color:#000;padding:0;} .wrap{border:none;background:#fff;max-width:none;}
h1{color:#000;} h2{color:#000;border-color:#000;} .sub,.meta,.card .l,th,.foot{color:#333;}
.card,.fbox{background:#f6f6f6;border-color:#999;} td.mac{color:#000;}
.badge{border:1px solid #000;} tr.flag-red td{background:#ffe3e3;} tr.flag-amber td{background:#fff3d6;}
.foot .hash{color:#000;} @page{margin:14mm;}}
""".strip()


def _html_badge(status):
    cls = {"VERIFIED": "b-verified", "UNRESOLVED": "b-unresolved"}.get(status, "b-unverified")
    return "<span class='badge {c}'>{s}</span>".format(c=cls, s=_e(status))


def _html_flag_cls(d):
    if not d["in_baseline"] or d["laa"]:
        return "flag-red"
    if d["status"] == "UNRESOLVED":
        return "flag-amber"
    return ""


def render_html(m):
    return (
        "<!DOCTYPE html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>DSG TSCM — Network Validation Report</title><style>" + _HTML_CSS +
        "</style></head><body><div class=wrap>"
        "<h1>TSCM NETWORK VALIDATION REPORT</h1>"
        "<div class=sub><b>Data Specialist Group</b> · Surveillance Specialist Group, LLC · "
        "FL PI License " + FL_PI_LICENSE + "</div>"
        "<div class=sub>" + SITE + " &nbsp;·&nbsp; " + PHONE + "</div>"
        "<div class=meta><b>Case:</b> " + _e(m["case"] or "—") +
        " &nbsp;·&nbsp; <b>Examiner:</b> " + _e(m["examiner"] or "—") +
        "<br><b>Date:</b> " + _e(m["date"]) + " &nbsp;·&nbsp; <b>Time:</b> " + _e(m["time"]) +
        ("" if not m.get("capture") else " &nbsp;·&nbsp; <b>Capture:</b> " + _e(m["capture"])) +
        "</div>"
        "<div class=cards>" + _summary_cards(m) + "</div>"
        "<h2>ACCESS POINTS (" + str(len(m["aps"])) + ")</h2>" + _ap_table(m, _html_badge) +
        "<h2>CLIENT DEVICES (" + str(len(m["devices"])) + ")</h2>" +
        _dev_table(m, _html_badge, _html_flag_cls) +
        "<h2>FLAGGED FINDINGS</h2><div class=findings>"
        "<div class='fbox amber'><h3>△ UNRESOLVED DEVICES ("
        + str(len(m["flagged"]["unresolved"])) + ") — ADVISORY</h3><ul>"
        + _flagged_list(m["flagged"]["unresolved"], "unresolved") + "</ul></div>"
        "<div class='fbox red'><h3>✖ NOT FOUND IN BASELINE ("
        + str(len(m["flagged"]["not_found"])) + ") — CRITICAL</h3><ul>"
        + _flagged_list(m["flagged"]["not_found"], "not_found") + "</ul></div>"
        "<div class='fbox red'><h3>✖ LOCALLY ADMINISTERED MACs ("
        + str(len(m["flagged"]["laa"])) + ") — CRITICAL</h3><ul>"
        + _flagged_list(m["flagged"]["laa"], "laa") + "</ul></div>"
        "</div>"
        "<div class=foot>Generated " + _e(m["date"]) + " " + _e(m["time"]) +
        " by DSG TSCM Triage · Network Validation<br>"
        "Report SHA256: <span class=hash>" + _e(m["hash"]) + "</span></div>"
        "</div></body></html>")


# ── PDF (print-friendly) ────────────────────────────────────────────────────
def _pdf_css(m):
    return ("""
@page{size:letter;margin:16mm 14mm 20mm;
 @bottom-center{content:"Page " counter(page) " of " counter(pages);font-size:8pt;color:#666;}
 @bottom-left{content:"SHA256: """ + m["hash"][:40] + """…";font-size:7pt;color:#888;}}
*{box-sizing:border-box;} body{font-family:'DejaVu Sans Mono','Courier New',monospace;
 color:#000;background:#fff;font-size:10pt;margin:0;}
.logo{font-family:Helvetica,Arial,sans-serif;font-weight:bold;font-size:18pt;letter-spacing:2px;color:#000;}
.org{font-size:9pt;color:#333;margin:2px 0 1px;} .lic{font-size:8.5pt;color:#333;}
hr{border:none;border-top:2px solid #000;margin:8px 0 12px;}
h2{font-size:11pt;letter-spacing:1px;border-bottom:1px solid #000;padding-bottom:3px;margin:18px 0 6px;}
.meta{font-size:9pt;line-height:1.6;} .meta b{font-weight:bold;}
.sum{width:100%;border-collapse:collapse;margin:10px 0;} .sum td{border:1px solid #999;padding:6px 8px;font-size:9pt;text-align:center;}
.sum .n{font-size:15pt;font-weight:bold;} .sum .l{font-size:7.5pt;color:#444;letter-spacing:1px;}
table{width:100%;border-collapse:collapse;font-size:8.5pt;margin-top:4px;}
th,td{border:1px solid #999;padding:4px 6px;text-align:left;vertical-align:top;}
th{background:#e8e8e8;font-weight:bold;}
tr.flag-red td{background:#ffd9d9;} tr.flag-amber td{background:#fff0cf;}
.badge{font-weight:bold;} .b-unresolved{color:#a00;} .b-verified{color:#036;}
.fbox{border:1px solid #999;border-left:5px solid #999;padding:8px 12px;margin:8px 0;page-break-inside:avoid;}
.fbox.red{border-left-color:#c00;background:#fff2f2;} .fbox.amber{border-left-color:#d68a00;background:#fffaf0;}
.fbox h3{margin:0 0 5px;font-size:9.5pt;} .fbox.red h3{color:#c00;} .fbox.amber h3{color:#a86000;}
.fbox ul{margin:0;padding-left:18px;font-size:8.5pt;} .fbox li.none{list-style:none;margin-left:-18px;color:#666;}
.foot{margin-top:20px;border-top:1px solid #000;padding-top:8px;font-size:7.5pt;color:#333;word-break:break-all;}
""").strip()


def _pdf_badge(status):
    cls = {"VERIFIED": "b-verified", "UNRESOLVED": "b-unresolved"}.get(status, "")
    return "<span class='badge {c}'>{s}</span>".format(c=cls, s=_e(status))


def render_pdf_html(m):
    su = m["summary"]
    sumrow = ("<table class=sum><tr>"
              "<td><div class=n>%d</div><div class=l>APs OBSERVED</div></td>"
              "<td><div class=n>%d</div><div class=l>VERIFIED</div></td>"
              "<td><div class=n>%d</div><div class=l>UNRESOLVED</div></td>"
              "<td><div class=n>%d</div><div class=l>NOT FOUND</div></td>"
              "</tr></table>") % (su["aps_observed"], su["verified"],
                                  su["unresolved"], su["not_found"])
    return (
        "<!DOCTYPE html><html><head><meta charset=utf-8><style>" + _pdf_css(m) +
        "</style></head><body>"
        "<div class=logo>DATA SPECIALIST GROUP</div>"
        "<div class=org>Surveillance Specialist Group, LLC — TSCM Network Validation Report</div>"
        "<div class=lic>FL PI License " + FL_PI_LICENSE + " · " + SITE + " · " + PHONE + "</div><hr>"
        "<div class=meta><b>Case:</b> " + _e(m["case"] or "—") +
        " &nbsp; <b>Examiner:</b> " + _e(m["examiner"] or "—") +
        "<br><b>Date:</b> " + _e(m["date"]) + " &nbsp; <b>Time:</b> " + _e(m["time"]) +
        ("" if not m.get("capture") else " &nbsp; <b>Capture:</b> " + _e(m["capture"])) +
        "</div>"
        "<h2>NETWORK VALIDATION SUMMARY</h2>" + sumrow +
        "<h2>ACCESS POINTS (" + str(len(m["aps"])) + ")</h2>" + _ap_table(m, _pdf_badge) +
        "<h2>CLIENT DEVICES (" + str(len(m["devices"])) + ")</h2>" +
        _dev_table(m, _pdf_badge, _html_flag_cls) +
        "<h2>FLAGGED FINDINGS</h2>"
        "<div class='fbox amber'><h3>UNRESOLVED DEVICES ("
        + str(len(m["flagged"]["unresolved"])) + ") — ADVISORY</h3><ul>"
        + _flagged_list(m["flagged"]["unresolved"], "u") + "</ul></div>"
        "<div class='fbox red'><h3>NOT FOUND IN BASELINE ("
        + str(len(m["flagged"]["not_found"])) + ") — CRITICAL</h3><ul>"
        + _flagged_list(m["flagged"]["not_found"], "n") + "</ul></div>"
        "<div class='fbox red'><h3>LOCALLY ADMINISTERED MACs ("
        + str(len(m["flagged"]["laa"])) + ") — CRITICAL</h3><ul>"
        + _flagged_list(m["flagged"]["laa"], "l") + "</ul></div>"
        "<div class=foot>Generated " + _e(m["date"]) + " " + _e(m["time"]) +
        " · DSG TSCM Triage · Network Validation<br>Report SHA256: " + _e(m["hash"]) +
        "</div></body></html>")


def render_pdf(m):
    """Return (pdf_bytes, None) or (None, error_message).

    Prefers WeasyPrint; falls back to wkhtmltopdf if WeasyPrint is not installed.
    """
    doc = render_pdf_html(m)
    try:
        from weasyprint import HTML
        return HTML(string=doc).write_pdf(), None
    except ImportError:
        pass
    except Exception as e:  # WeasyPrint present but failed to render
        return None, "weasyprint error: %s" % e

    tmp_html = out_pdf = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                         encoding="utf-8") as tf:
            tf.write(doc)
            tmp_html = tf.name
        out_pdf = tmp_html[:-5] + ".pdf"
        r = subprocess.run(
            ["wkhtmltopdf", "--enable-local-file-access", "--quiet",
             "--footer-font-size", "8",
             "--footer-center", "Page [page] of [topage]",
             "--footer-left", "SHA256: " + m["hash"][:32],
             tmp_html, out_pdf],
            capture_output=True)
        if r.returncode != 0 or not os.path.exists(out_pdf):
            return None, "wkhtmltopdf failed: " + r.stderr.decode("utf-8", "ignore")[:200]
        with open(out_pdf, "rb") as f:
            return f.read(), None
    except FileNotFoundError:
        return None, "no PDF engine available (install weasyprint or wkhtmltopdf)"
    except Exception as e:
        return None, str(e)
    finally:
        for p in (tmp_html, out_pdf):
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
