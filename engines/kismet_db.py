"""
kismet_db.py — DSG TSCM Triage Kismet engine (Wi-Fi access points + clients).

Ported from DSG Sentinel. Built against the REAL Kismet .kismet SQLite schema.
Verified facts:

  TABLE devices columns:
    first_time INT, last_time INT, devkey TEXT, phyname TEXT, devmac TEXT,
    strongest_signal INT, min/max/avg lat/lon REAL, bytes_data INT,
    type TEXT, device BLOB

  * phyname is only ever 'IEEE802.11' or 'Bluetooth'.
  * All rich fields (name, vendor, rssi, packet count, probed SSIDs) live inside
    the `device` JSON BLOB under kismet.device.base.* keys.
  * Kismet already resolves the vendor into kismet.device.base.manuf.
  * Wi-Fi association topology: an AP's BLOB carries its associated-client MAC
    map; a client's BLOB carries the BSSID it last joined.

The database is opened READ-ONLY so a live Kismet writer is never disturbed, and
connection failures degrade gracefully to empty results (Kismet not running).
"""

import glob
import gzip
import json
import logging
import os
import sqlite3

logger = logging.getLogger("tscm.kismet_db")

# ── phyname / type constants ────────────────────────────────────────────────
PHY_WIFI = "IEEE802.11"

CAT_WIFI_AP = "WIFI_AP"
CAT_WIFI_CLIENT = "WIFI_CLIENT"
CAT_UNKNOWN = "UNKNOWN"

_AP_TYPES = ("Wi-Fi AP", "Wi-Fi WDS AP")
_CATEGORY_SQL = {
    "all":         ("", []),
    "wifi":        ("phyname = ?", [PHY_WIFI]),
    # AP selection is by phyname + device type ONLY — deliberately no channel,
    # band, or signal predicate, so 2.4GHz, 5GHz and 6GHz APs are all returned
    # and weak (e.g. distant 5GHz) APs are never dropped by a signal floor.
    "wifi_ap":     ("phyname = ? AND type IN (?, ?)", [PHY_WIFI, *_AP_TYPES]),
    "wifi_client": ("phyname = ? AND type NOT IN (?, ?)", [PHY_WIFI, *_AP_TYPES]),
}

# ── base JSON key paths inside the device BLOB ──────────────────────────────
_K_BASE = "kismet.device.base."
_K_NAME = _K_BASE + "name"
_K_COMMON = _K_BASE + "commonname"
_K_MANUF = _K_BASE + "manuf"
_K_TYPE = _K_BASE + "type"
_K_CHANNEL = _K_BASE + "channel"
_K_FREQ = _K_BASE + "frequency"
_K_CRYPT = _K_BASE + "crypt"
_K_PACKETS = _K_BASE + "packets.total"
_K_SIGNAL = _K_BASE + "signal"


def _norm_mac(mac):
    return (mac or "").strip().upper()


def _decode_blob(blob):
    """Return parsed JSON dict from a device BLOB, tolerating gzip / bytes."""
    if blob is None:
        return {}
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    if isinstance(blob, bytes):
        if blob[:2] == b"\x1f\x8b":  # gzip magic
            try:
                blob = gzip.decompress(blob)
            except OSError:
                pass
        try:
            blob = blob.decode("utf-8", "replace")
        except Exception:
            return {}
    try:
        return json.loads(blob)
    except (ValueError, TypeError):
        return {}


def categorize(phyname, dtype):
    if phyname == PHY_WIFI:
        if dtype == "Wi-Fi AP" or dtype == "Wi-Fi WDS AP":
            return CAT_WIFI_AP
        return CAT_WIFI_CLIENT
    return CAT_UNKNOWN


class KismetDB:
    """Read-only accessor for a Kismet .kismet SQLite log."""

    def __init__(self, db_path):
        self.db_path = db_path

    # ── connection helpers ──────────────────────────────────────────────
    def _connect(self):
        # Open read-only so a live Kismet writer is never disturbed.
        uri = "file:{}?mode=ro".format(self.db_path.replace("?", "%3f"))
        conn = sqlite3.connect(uri, uri=True, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _query(self, sql, params=()):
        try:
            conn = self._connect()
        except sqlite3.Error as e:
            # Kismet not running / DB locked / missing — degrade to empty.
            logger.warning("kismet db connect failed: %s", e)
            return []
        try:
            return conn.execute(sql, params).fetchall()
        except sqlite3.Error as e:
            logger.warning("kismet db query failed: %s", e)
            return []
        finally:
            conn.close()

    # ── row -> normalized dict ──────────────────────────────────────────
    def _row_to_device(self, row):
        d = _decode_blob(row["device"])
        phyname = row["phyname"]
        dtype = row["type"] or d.get(_K_TYPE, "")
        category = categorize(phyname, dtype)

        sig = d.get(_K_SIGNAL) or {}
        last_signal = sig.get("kismet.common.signal.last_signal")
        rssi = last_signal if last_signal not in (None, 0) else row["strongest_signal"]

        name = (d.get(_K_NAME) or "").strip()
        common = (d.get(_K_COMMON) or "").strip()

        dev = {
            "mac": row["devmac"],
            "phyname": phyname,
            "type": dtype,
            "category": category,
            "name": name or common or row["devmac"],
            "vendor": (d.get(_K_MANUF) or "").strip() or "Unknown",
            "ssid": _extract_primary_ssid(d),
            "first_seen": row["first_time"],
            "last_seen": row["last_time"],
            "num_packets": d.get(_K_PACKETS, 0) or 0,
            "rssi": rssi,
            "channel": d.get(_K_CHANNEL, ""),
            "frequency": d.get(_K_FREQ, 0),
            "crypt": d.get(_K_CRYPT, ""),
        }
        dot11 = d.get("dot11.device") or {}
        if category == CAT_WIFI_AP:
            acm = dot11.get("dot11.device.associated_client_map") or {}
            dev["client_macs"] = ([_norm_mac(m) for m in acm.keys()]
                                  if isinstance(acm, dict) else [])
            dev["client_count"] = (len(dev["client_macs"])
                                   or dot11.get("dot11.device.num_associated_clients") or 0)
        elif category == CAT_WIFI_CLIENT:
            dev["last_bssid"] = _norm_mac(dot11.get("dot11.device.last_bssid") or "")
        return dev

    # ── public API ──────────────────────────────────────────────────────
    def get_all_devices(self, since_epoch=0, category="all", limit=None):
        frag, cparams = _CATEGORY_SQL.get((category or "all").lower(),
                                          _CATEGORY_SQL["all"])
        sql = ("SELECT first_time, last_time, phyname, devmac, strongest_signal, "
               "type, device FROM devices WHERE last_time >= ?")
        params = [since_epoch]
        if frag:
            sql += " AND " + frag
            params.extend(cparams)
        sql += " ORDER BY last_time DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        return [self._row_to_device(r) for r in self._query(sql, tuple(params))]

    def is_available(self):
        """True if the DB can be opened and holds a devices table."""
        rows = self._query("SELECT COUNT(*) AS n FROM devices")
        return bool(rows)


# ── SSID extraction helper ──────────────────────────────────────────────────
def _extract_primary_ssid(d):
    dot11 = d.get("dot11.device") or {}
    adv = dot11.get("dot11.device.advertised_ssid_map") or []
    if adv:
        ssid = (adv[0].get("dot11.advertisedssid.ssid") or "").strip()
        if ssid:
            return ssid
    last = dot11.get("dot11.device.last_beaconed_ssid_record") or {}
    if isinstance(last, dict):
        s = (last.get("dot11.advertisedssid.ssid") or "").strip()
        if s:
            return s
    return ""


# ── db path resolution ──────────────────────────────────────────────────────
# Default search location for Kismet capture logs. Overridable so a Raspberry Pi
# / USB deployment can point at an external drive.
DEFAULT_GLOB = os.environ.get("KISMET_GLOB", "/home/pentester/*.kismet")


def resolve_db_path(pattern=None):
    """Return the most recently modified .kismet file, or None if there are none.

    An explicit KISMET_DB env var wins; otherwise the newest match of `pattern`
    (default DEFAULT_GLOB) is chosen.
    """
    explicit = os.environ.get("KISMET_DB", "").strip()
    if explicit:
        return explicit if os.path.exists(explicit) else None
    pattern = pattern or DEFAULT_GLOB
    matches = glob.glob(pattern)
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


def open_db(pattern=None):
    """Return a KismetDB for the resolved path, or None if no capture is found."""
    path = resolve_db_path(pattern)
    return KismetDB(path) if path else None
