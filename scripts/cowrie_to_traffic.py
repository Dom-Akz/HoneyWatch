#!/usr/bin/env python3

"""
Cowrie Honeypot to Traffic Log Converter
Converts Cowrie JSON logs to traffic_log.csv format for DDoS detection pipeline
Runs on Arch Linux, fetches logs from Ubuntu VM via SSH
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path

# ============ CONFIGURATION ============
UBUNTU_VM_IP = "192.168.1.8"
UBUNTU_USER = "vboxuser"
COWRIE_LOG_PATH = "~/honeypot/logs/cowrie.json"

# Project paths (on Arch)
PROJECT_ROOT = Path(__file__).parent.parent
TRAFFIC_LOG = PROJECT_ROOT / "data" / "traffic_log.csv"
ALERTS_FILE = PROJECT_ROOT / "data" / "alerts.jsonl"
DATA_FOLDER = PROJECT_ROOT / "data"

# Cowrie specific
KNOWN_PORTS = {22: "SSH", 23: "Telnet", 2222: "SSH-Honeypot"}


# ssh into Ubuntu VM and fetch recent Cowrie logs
def fetch_cowrie_logs(limit=100):
    cmd = f"ssh {UBUNTU_USER}@{UBUNTU_VM_IP} 'tail -{limit} {COWRIE_LOG_PATH}'"

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            print(f"[!] SSH error: {result.stderr}")
            return []

        logs = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        # save the logs inside data folder
        save_log(logs)
        return logs
    except subprocess.TimeoutExpired:
        print("[!] SSH timeout")
        return []
    except Exception as e:
        print(f"[!] Error: {e}")
        return []


# Save Cowrie log entries to a JSON file in the data folder.
def save_log(log_entries):
    os.makedirs(DATA_FOLDER, exist_ok=True)
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(DATA_FOLDER, f"honeypot_attacks_{timestamp}.csv")

    df = pd.DataFrame(log_entries)
    df.to_csv(filepath, index=False, encoding="utf-8")


def cowrie_to_traffic_row(cowrie_log, dst_ip):
    timestamp = cowrie_log.get("timestamp", datetime.now(timezone.utc).isoformat())
    src_ip = cowrie_log.get("src_ip", "0.0.0.0")

    # Determine protocol based on port
    dst_port = cowrie_log.get("dst_port", 2222)
    protocol = "TCP"
    length = 74  # Typical TCP SYN packet size

    # Format timestamp to match capture.py format
    if "T" not in timestamp:
        timestamp = timestamp.replace(" ", "T")
    if not timestamp.endswith("Z"):
        timestamp = timestamp + "Z"

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "length": length,
        # Extra fields for context
        "username": cowrie_log.get("username", ""),
        "password": cowrie_log.get("password", ""),
        "eventid": cowrie_log.get("eventid", ""),
    }


def ensure_traffic_log():
    if not TRAFFIC_LOG.exists():
        TRAFFIC_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(TRAFFIC_LOG, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "length"]
            )
            writer.writeheader()
        print(f"[+] Created {TRAFFIC_LOG}")


def append_to_traffic_log(rows):
    """Append rows to traffic_log.csv"""
    if not rows:
        return 0

    ensure_traffic_log()

    with open(TRAFFIC_LOG, "a", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "length"]
        )
        for row in rows:
            writer.writerow(
                {
                    k: row[k]
                    for k in ["timestamp", "src_ip", "dst_ip", "protocol", "length"]
                }
            )

    return len(rows)


def generate_direct_alert(cowrie_log):
    """Generate a direct alert for the dashboard (bypass CSV pipeline)"""
    alert = {
        "window_start": datetime.now(timezone.utc).isoformat(),
        "window_end": datetime.now(timezone.utc).isoformat(),
        "predicted_label": 1,  # 1 = attack detected
        "probability": 0.95,
        "pkts": 1,
        "unique_srcs": 1,
        "entropy_src": 0.0,
        "top_srcs": {cowrie_log.get("src_ip", "unknown"): 1},
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "source": "cowrie_honeypot",
        "username": cowrie_log.get("username", ""),
        "password": cowrie_log.get("password", ""),
    }

    # Append to alerts.jsonl
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

    return alert


def run_once(limit=50, dst_ip=None, direct_alerts=True):
    """Run one conversion cycle"""
    if dst_ip is None:
        dst_ip = UBUNTU_VM_IP

    print(f"[*] Fetching Cowrie logs from {UBUNTU_USER}@{UBUNTU_VM_IP}...")
    logs = fetch_cowrie_logs(limit)

    if not logs:
        print("[!] No logs retrieved")
        return 0

    print(f"[*] Retrieved {len(logs)} log entries")

    # Filter for login attempts only
    attack_logs = [l for l in logs if "login" in l.get("eventid", "")]
    print(f"[*] Found {len(attack_logs)} login attacks")

    if direct_alerts:
        # Method 1: Generate direct alerts (bypasses CSV)
        for log in attack_logs:
            generate_direct_alert(log)
            print(
                f"[ALERT] SSH brute from {log.get('src_ip')} - {log.get('username')}:{log.get('password')}"
            )
    else:
        # Method 2: Convert to traffic_log.csv format
        rows = [cowrie_to_traffic_row(log, dst_ip) for log in attack_logs]
        count = append_to_traffic_log(rows)
        print(f"[+] Added {count} rows to {TRAFFIC_LOG}")

    return len(attack_logs)


def continuous_mode(interval=5, dst_ip=None):
    """Continuously monitor and forward Cowrie logs"""
    print("[*] Starting continuous Cowrie log forwarder")
    print(f"[*] Ubuntu VM: {UBUNTU_USER}@{UBUNTU_VM_IP}")
    print(f"[*] Interval: {interval} seconds")
    print("[*] Press Ctrl+C to stop\n")

    seen_logs = set()

    while True:
        logs = fetch_cowrie_logs(100)

        for log in logs:
            # Create a unique ID for this log
            log_id = (
                f"{log.get('timestamp')}_{log.get('src_ip')}_{log.get('username', '')}"
            )

            if log_id in seen_logs:
                continue
            seen_logs.add(log_id)

            # Only process login attempts
            if "login" in log.get("eventid", ""):
                generate_direct_alert(log)
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] ALERT: {log.get('src_ip')} -> {log.get('username')}:{log.get('password')}"
                )

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        description="Forward Cowrie honeypot logs to DDoS detection pipeline"
    )
    parser.add_argument("--mode", choices=["once", "continuous"], default="once")
    parser.add_argument("--limit", type=int, default=50, help="Number of logs to fetch")
    parser.add_argument(
        "--interval", type=int, default=5, help="Polling interval in seconds"
    )
    parser.add_argument("--dst-ip", help="Destination IP (your Ubuntu VM IP)")
    parser.add_argument(
        "--direct-alerts",
        action="store_true",
        default=True,
        help="Write directly to alerts.jsonl",
    )

    args = parser.parse_args()

    dst_ip = args.dst_ip or UBUNTU_VM_IP

    if args.mode == "once":
        count = run_once(args.limit, dst_ip, args.direct_alerts)
        print(f"[+] Done. Processed {count} attacks.")
    else:
        continuous_mode(args.interval, dst_ip)


if __name__ == "__main__":
    main()
