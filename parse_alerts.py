"""
parse_alerts.py
---------------
Export Wazuh alert logs (/var/ossec/logs/alerts/alerts.log) ke CSV
untuk diproses oleh AI triage model.

Usage (di Wazuh Manager):
    python3 /home/azureuser/parse_alerts.py

Output:
    wazuh_alerts.csv  — siap dipakai di SOC_DDoS_Triage_Notebook.ipynb
"""

import re
import csv
import os
from datetime import datetime

# ── Konfigurasi ──────────────────────────────────────────────────────────────
LOG_FILE   = "/var/ossec/logs/alerts/alerts.log"
OUTPUT_CSV = "wazuh_alerts.csv"

# ── Regex pola alert Wazuh ───────────────────────────────────────────────────
RE_HEADER    = re.compile(
    r"\*\* Alert (\d+\.\d+):\s*(.*?)\s*-\s*([\w,\.]+)"
)
RE_RULE      = re.compile(
    r"Rule:\s*(\d+)\s*\(level\s*(\d+)\)\s*->\s*'(.+?)'"
)
RE_SRCIP     = re.compile(
    r"Src IP:\s*(\S+)"
)
RE_DSTIP     = re.compile(
    r"Dst IP:\s*(\S+)"
)
RE_SRCUSER   = re.compile(
    r"Src User:\s*(\S+)"
)


def parse_alerts(log_path: str) -> list[dict]:
    """Parse alerts.log Wazuh, return list of alert dicts."""
    alerts = []
    current: dict = {}

    with open(log_path, "r", errors="replace") as f:
        lines = f.readlines()

    full_log_lines: list[str] = []

    def flush():
        """Simpan alert yang sedang diproses ke list."""
        if current.get("alert_id"):
            current["full_log"] = " | ".join(full_log_lines).strip()
            alerts.append(dict(current))

    for line in lines:
        line = line.rstrip("\n")

        # ── Baris header alert baru ──────────────────────────────────────────
        m = RE_HEADER.match(line)
        if m:
            flush()
            current = {}
            full_log_lines = []

            epoch_str = m.group(1)
            # Wazuh timestamp: seconds.milliseconds sejak epoch
            ts = datetime.utcfromtimestamp(float(epoch_str.split(".")[0]))
            current["alert_id"]   = epoch_str
            current["timestamp"]  = ts.strftime("%Y-%m-%d %H:%M:%S")
            current["location"]   = m.group(2).strip()
            current["groups"]     = m.group(3).strip()
            current["rule_id"]       = ""
            current["rule_level"]    = ""
            current["rule_description"] = ""
            current["src_ip"]     = ""
            current["dst_ip"]     = ""
            current["src_user"]   = ""
            current["full_log"]   = ""
            continue

        # ── Baris rule ───────────────────────────────────────────────────────
        m = RE_RULE.match(line)
        if m and current.get("alert_id"):
            current["rule_id"]          = m.group(1)
            current["rule_level"]       = int(m.group(2))
            current["rule_description"] = m.group(3)
            continue

        # ── Baris Src/Dst IP & user ──────────────────────────────────────────
        m = RE_SRCIP.search(line)
        if m and current.get("alert_id"):
            current["src_ip"] = m.group(1)

        m = RE_DSTIP.search(line)
        if m and current.get("alert_id"):
            current["dst_ip"] = m.group(1)

        m = RE_SRCUSER.search(line)
        if m and current.get("alert_id"):
            current["src_user"] = m.group(1)

        # ── Semua baris lain jadi full_log ───────────────────────────────────
        if current.get("alert_id") and line.strip():
            full_log_lines.append(line.strip())

    flush()  # simpan alert terakhir
    return alerts


def save_csv(alerts: list[dict], output_path: str):
    """Tulis list alert ke CSV."""
    if not alerts:
        print("Tidak ada alert yang berhasil di-parse.")
        return

    fieldnames = [
        "alert_id", "timestamp", "location", "groups",
        "rule_id", "rule_level", "rule_description",
        "src_ip", "dst_ip", "src_user", "full_log",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)

    print(f"Exported {len(alerts)} alerts → {output_path}")


def print_summary(alerts: list[dict]):
    """Tampilkan ringkasan seperti di screenshot terminal."""
    from collections import Counter

    descriptions = [a["rule_description"] for a in alerts if a["rule_description"]]
    counter = Counter(descriptions)

    print("\nTop 10 rule descriptions:")
    print(f"{'rule_description':<55} {'count':>6}")
    for desc, count in counter.most_common(10):
        print(f"{desc:<55} {count:>6}")


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        print(f"[ERROR] File tidak ditemukan: {LOG_FILE}")
        print("Pastikan script dijalankan di Wazuh Manager sebagai user dengan akses ke /var/ossec/")
        exit(1)

    print(f"Membaca {LOG_FILE} ...")
    alerts = parse_alerts(LOG_FILE)
    save_csv(alerts, OUTPUT_CSV)
    print_summary(alerts)
