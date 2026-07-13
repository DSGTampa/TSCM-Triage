"""
baseline_mgr.py — enrolled known-device allowlist for the examiner.

Ported into DSG TSCM Triage from DSG Sentinel. Enrollment records the devices
the examiner has physically accounted for (VERIFIED) plus the client's own
access points into data/baseline.json. Afterwards, any device whose MAC is NOT
in the baseline is a candidate arrival worth following up.
"""

import json
import os
import threading
import time


class BaselineManager:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._cache = None
        self._mtime = None

    # ── persistence ─────────────────────────────────────────────────────
    def _load(self):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            mtime = None
        if self._cache is not None and mtime == self._mtime:
            return self._cache
        data = {"enrolled_ts": None, "devices": {}}
        if mtime is not None:
            try:
                with open(self.path, "r") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict) and "devices" in loaded:
                    data = loaded
            except (OSError, ValueError):
                pass
        self._cache = data
        self._mtime = mtime
        return data

    def _save(self, data):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
        self._cache = data
        try:
            self._mtime = os.path.getmtime(self.path)
        except OSError:
            self._mtime = None

    # ── public API ──────────────────────────────────────────────────────
    def is_known(self, mac):
        return _norm(mac) in self._load()["devices"]

    def add(self, mac, label="", category="", vendor=""):
        with self._lock:
            data = dict(self._load())
            data.setdefault("devices", {})
            data["devices"] = dict(data["devices"])
            data["devices"][_norm(mac)] = {
                "label": label or "",
                "category": category,
                "vendor": vendor,
                "enrolled_ts": int(time.time()),
            }
            self._save(data)
        return True

    def add_many(self, entries):
        """Add many devices. `entries` may be a list of bare MAC strings or of
        {mac, label, category, vendor} dicts. Existing entries are preserved."""
        with self._lock:
            data = dict(self._load())
            devs = dict(data.get("devices", {}))
            now = int(time.time())
            for e in entries:
                if isinstance(e, str):
                    mac, rec = e, {}
                else:
                    mac = e.get("mac")
                    rec = e
                if not mac:
                    continue
                devs.setdefault(_norm(mac), {
                    "label": rec.get("label", ""),
                    "category": rec.get("category", ""),
                    "vendor": rec.get("vendor", ""),
                    "enrolled_ts": now,
                })
            data["devices"] = devs
            if data.get("enrolled_ts") is None:
                data["enrolled_ts"] = now
            self._save(data)
        return len(entries)

    def remove(self, mac):
        with self._lock:
            data = dict(self._load())
            devs = dict(data.get("devices", {}))
            existed = devs.pop(_norm(mac), None) is not None
            data["devices"] = devs
            self._save(data)
        return existed

    def clear(self):
        with self._lock:
            self._save({"enrolled_ts": None, "devices": {}})
        return True

    def get_summary(self):
        data = self._load()
        devs = data["devices"]
        summary = {"total": len(devs), "verified": 0, "aps": 0,
                   "enrolled_ts": data.get("enrolled_ts")}
        for e in devs.values():
            cat = e.get("category", "")
            if cat == "VERIFIED":
                summary["verified"] += 1
            elif cat == "WIFI_AP":
                summary["aps"] += 1
        return summary

    def get_all(self):
        return dict(self._load()["devices"])


def _norm(mac):
    return (mac or "").strip().upper()
