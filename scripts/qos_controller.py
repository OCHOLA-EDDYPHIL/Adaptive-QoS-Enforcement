import subprocess
import time
import csv
from datetime import datetime

# === CONFIGURATION ===
ADAPTIVE_MODE = False  # <-- Toggle to True during the experiment
MONITOR_INTERVAL = 5   # seconds
INTERFACES = ["r1-eth0", "r1-eth1", "r1-eth2"]
CAKE_TINS = 8
CSV_LOG = "qos_metrics.csv"

# === Monitoring Helpers ===
def parse_cake_stats(iface):
    output = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", iface], text=True)
    lines = output.splitlines()
    stats = {f"Tin{i}_pkts": 0 for i in range(CAKE_TINS)}
    stats.update({f"Tin{i}_bytes": 0 for i in range(CAKE_TINS)})

    current_tin = -1
    for line in lines:
        line = line.strip()
        if line.startswith("Tin"):
            try:
                current_tin = int(line.split()[1])
            except:
                continue
        elif "pkts" in line and current_tin >= 0:
            parts = line.split()
            try:
                stats[f"Tin{current_tin}_pkts"] = int(parts[0])
                stats[f"Tin{current_tin}_bytes"] = int(parts[1])
            except:
                continue
    return stats

# === Adaptive Policy (Simple Threshold-Based Stub) ===
def adapt_qos_policy(iface, stats):
    if not ADAPTIVE_MODE:
        return

    tin2_pkts = stats.get("Tin2_pkts", 0)
    tin2_bytes = stats.get("Tin2_bytes", 0)

    if tin2_pkts > 500:
        print(f"[!] High volume in Tin2 on {iface}. Considering policy adjustment...")
        # Placeholder for actual tc/iptables/tc-cake changes
        # e.g., deprioritize, change weights, alter bandwidth

# === Logging ===
def write_metrics_to_csv(timestamp, iface, stats):
    fieldnames = ["timestamp", "iface"] + list(stats.keys())
    file_exists = False
    try:
        with open(CSV_LOG, "r"): file_exists = True
    except FileNotFoundError:
        pass

    with open(CSV_LOG, "a", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        row = {"timestamp": timestamp, "iface": iface}
        row.update(stats)
        writer.writerow(row)

# === Main Loop ===
if __name__ == "__main__":
    print("[*] QoS Controller started.")
    print(f"[*] Adaptive mode is {'ON' if ADAPTIVE_MODE else 'OFF'}.")

    while True:
        for iface in INTERFACES:
            stats = parse_cake_stats(iface)
            ts = datetime.now().isoformat()
            write_metrics_to_csv(ts, iface, stats)
            adapt_qos_policy(iface, stats)
        time.sleep(MONITOR_INTERVAL)
