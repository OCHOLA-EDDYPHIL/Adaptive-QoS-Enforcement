import subprocess
import time
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from threading import Lock, Thread

# === CONFIGURATION ===
ADAPTIVE_MODE = True  # <-- Toggle to True during the experiment
MONITOR_INTERVAL = 15   # seconds
INTERFACES = ["r1-eth0"]  # LAN interface only in switch-based topology
CAKE_TINS = 8
CSV_LOG = "performance/qos_metrics.csv"

# === Realtime Performance Monitoring State ===
flow_stats = defaultdict(lambda: {'fwd': [], 'bwd': [], 'start': None})
flow_lock = Lock()

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

# === Passive QoS Metric Estimation ===
def get_conntrack_key(pkt):
    if IP not in pkt or not (TCP in pkt or UDP in pkt):
        return None
    proto = 'TCP' if TCP in pkt else 'UDP'
    ip = pkt[IP]
    l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
    return (ip.src, l4.sport, ip.dst, l4.dport, proto)

def process_packet(pkt):
    key = get_conntrack_key(pkt)
    if key is None:
        return

    rev_key = (key[2], key[3], key[0], key[1], key[4])
    with flow_lock:
        if rev_key in flow_stats:
            k = rev_key
            direction = 'bwd'
        else:
            k = key
            direction = 'fwd'

        flow = flow_stats[k]
        if flow['start'] is None:
            flow['start'] = pkt.time
        flow[direction].append(pkt.time)

        if len(flow['fwd']) + len(flow['bwd']) >= 20:
            duration = max(flow['fwd'] + flow['bwd']) - flow['start']
            if duration >= 1:
                latency = sum([(t2 - t1) for t1, t2 in zip(flow[direction][:-1], flow[direction][1:])]) / (len(flow[direction]) - 1)
                jitter = sum([abs((t2 - t1) - latency) for t1, t2 in zip(flow[direction][:-1], flow[direction][1:])]) / (len(flow[direction]) - 1)
                print(f"[QoS METRIC] Flow {k} → latency: {latency*1000:.2f} ms | jitter: {jitter*1000:.2f} ms")
                flow_stats.pop(k)

# === Adaptive Policy ===
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

# === Sniffer Thread ===
def sniff_packets():
    print("[*] Starting passive packet monitor...")
    sniff(prn=process_packet, store=False, iface=INTERFACES[0])

# === Main Loop ===
if __name__ == "__main__":
    print("[*] QoS Controller started.")
    print(f"[*] Adaptive mode is {'ON' if ADAPTIVE_MODE else 'OFF'}.")

    Thread(target=sniff_packets, daemon=True).start()

    while True:
        for iface in INTERFACES:
            stats = parse_cake_stats(iface)
            ts = datetime.now().isoformat()
            write_metrics_to_csv(ts, iface, stats)
            adapt_qos_policy(iface, stats)
        time.sleep(MONITOR_INTERVAL)