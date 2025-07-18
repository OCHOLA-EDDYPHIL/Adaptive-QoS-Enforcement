import subprocess
import time
import csv
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from threading import Lock, Thread

# === CONFIGURATION ===
ADAPTIVE_MODE = True  # <-- Toggle to True during the experiment
MONITOR_INTERVAL = 15   # seconds
INTERFACES = ["r1-eth0", "r1-eth1"]
last_policy_change = {"mode": None, "timestamp": datetime.min}
RECONFIG_COOLDOWN = timedelta(seconds=10)  # Prevent rapid reconfigurations
CAKE_TINS = 8
CSV_LOG = "performance/qos_metrics.csv"

# === Realtime Performance Monitoring State ===
flow_stats = defaultdict(lambda: {'fwd': [], 'bwd': [], 'start': None})
flow_lock = Lock()

# === Monitoring Helpers ===
def parse_cake_stats(iface):
    """Parse CAKE qdisc statistics from tc command output"""
    print(f"\n[DEBUG] Running: tc -s qdisc show dev {iface}")

    try:
        output = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", iface], text=True)
        print(output)  # DEBUG full raw output
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to get tc stats: {e}")
        return {f"Tin{i}_pkts": 0 for i in range(CAKE_TINS)}

    # Initialize stats dictionary
    stats = {}
    for i in range(CAKE_TINS):
        stats[f"Tin{i}_pkts"] = 0
        stats[f"Tin{i}_bytes"] = 0

    lines = output.splitlines()

    # Look for the statistics table section
    tin_header_found = False
    pkts_line_idx = -1
    bytes_line_idx = -1

    for i, line in enumerate(lines):
        line = line.strip()

        # Find the tin header line
        if line.startswith("Tin 0") and "Tin 1" in line:
            tin_header_found = True
            print(f"[DEBUG] Found tin header at line {i}: {line}")
            continue

        # Find pkts line after tin header
        if tin_header_found and line.startswith("pkts"):
            pkts_line_idx = i
            print(f"[DEBUG] Found pkts line at {i}: {line}")

        # Find bytes line after tin header
        if tin_header_found and line.startswith("bytes"):
            bytes_line_idx = i
            print(f"[DEBUG] Found bytes line at {i}: {line}")
            break

    # Parse packet counts
    if pkts_line_idx >= 0:
        pkts_line = lines[pkts_line_idx].strip()
        # Split and skip the "pkts" label
        pkts_values = pkts_line.split()[1:]  # Skip "pkts" label
        print(f"[DEBUG] Parsed pkts values: {pkts_values}")

        for i, value in enumerate(pkts_values):
            if i < CAKE_TINS:
                try:
                    stats[f"Tin{i}_pkts"] = int(value)
                    print(f"[DEBUG] Tin{i}_pkts = {value}")
                except ValueError:
                    print(f"[WARNING] Could not parse pkts value '{value}' for Tin{i}")

    # Parse byte counts
    if bytes_line_idx >= 0:
        bytes_line = lines[bytes_line_idx].strip()
        # Split and skip the "bytes" label
        bytes_values = bytes_line.split()[1:]  # Skip "bytes" label
        print(f"[DEBUG] Parsed bytes values: {bytes_values}")

        for i, value in enumerate(bytes_values):
            if i < CAKE_TINS:
                try:
                    stats[f"Tin{i}_bytes"] = int(value)
                    print(f"[DEBUG] Tin{i}_bytes = {value}")
                except ValueError:
                    print(f"[WARNING] Could not parse bytes value '{value}' for Tin{i}")

    # Verify we got some data
    total_pkts = sum(stats[f"Tin{i}_pkts"] for i in range(CAKE_TINS))
    total_bytes = sum(stats[f"Tin{i}_bytes"] for i in range(CAKE_TINS))
    print(f"[DEBUG] Total parsed: {total_pkts} packets, {total_bytes} bytes")
    print(f"[DEBUG] CAKE stats for {iface}:")
    for tin in range(CAKE_TINS):
        pkts = stats.get(f"Tin{tin}_pkts", 0)
        bytes_ = stats.get(f"Tin{tin}_bytes", 0)
        print(f"  Tin{tin}: {pkts} pkts | {bytes_} bytes")
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
        direction = 'bwd' if rev_key in flow_stats else 'fwd'
        k = rev_key if rev_key in flow_stats else key

        flow = flow_stats[k]
        if flow['start'] is None:
            flow['start'] = pkt.time
        flow[direction].append(pkt.time)

        total_pkts = len(flow['fwd']) + len(flow['bwd'])
        if total_pkts >= 20:
            duration = max(flow['fwd'] + flow['bwd']) - flow['start']
            if duration >= 1:
                timestamps = flow[direction]
                latency = sum([(t2 - t1) for t1, t2 in zip(timestamps[:-1], timestamps[1:])]) / (len(timestamps) - 1)
                jitter = sum([abs((t2 - t1) - latency) for t1, t2 in zip(timestamps[:-1], timestamps[1:])]) / (len(timestamps) - 1)

                loss_est = 0
                if len(timestamps) > 1:
                    iats = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
                    expected_interval = sum(iats) / len(iats)
                    loss_est = sum(1 for iat in iats if iat > 2 * expected_interval)

                print(f"[QoS METRIC] Flow {k} → Latency: {latency*1000:.2f} ms | Jitter: {jitter*1000:.2f} ms | Loss events: {loss_est}")
                flow_stats.pop(k)

# === Adaptive Policy ===
def adapt_qos_policy(iface, stats):
    global last_policy_change

    if not ADAPTIVE_MODE:
        return

    now = datetime.now()
    if now - last_policy_change["timestamp"] < RECONFIG_COOLDOWN:
        return  # cooldown active

    # Corrected Tin assignments
    voip_pkts = stats.get("Tin3_pkts", 0)   # EF → Tin 3
    video_pkts = stats.get("Tin2_pkts", 0)  # AF41 → Tin 2
    bulk_pkts = stats.get("Tin0_pkts", 0)   # CS1 → Tin 0

    new_mode = None

    if voip_pkts > 100:
        new_mode = "voip_priority"
    elif video_pkts > 200 and voip_pkts < 50:
        new_mode = "video_priority"
    elif bulk_pkts > 500 and voip_pkts < 30 and video_pkts < 100:
        new_mode = "bulk_heavy"
    elif voip_pkts < 30 and video_pkts < 50 and bulk_pkts < 100:
        new_mode = "default"

    if new_mode and new_mode != last_policy_change["mode"]:
        print(f"[QoS] Switching policy: {last_policy_change['mode']} → {new_mode}")

        cmd = ["tc", "qdisc", "replace", "dev", iface, "root", "cake", "diffserv8", "nat"]
        if new_mode == "voip_priority":
            cmd += ["bandwidth", "10mbit", "rtt", "50ms"]
        elif new_mode == "video_priority":
            cmd += ["bandwidth", "10mbit", "rtt", "80ms"]
        elif new_mode == "bulk_heavy":
            cmd += ["bandwidth", "7mbit", "rtt", "100ms"]
        elif new_mode == "default":
            cmd += ["bandwidth", "10mbit", "rtt", "100ms"]

        print(f"[DEBUG] Running tc command: {' '.join(cmd)}")
        subprocess.run(cmd)
        last_policy_change = {"mode": new_mode, "timestamp": now}
    else:
        print(f"[DEBUG] No policy change needed. Current mode: {last_policy_change['mode']}")

# === Logging ===
def write_metrics_to_csv(timestamp, iface, stats):
    fieldnames = ["timestamp", "iface"] + list(stats.keys())
    file_exists = False
    try:
        with open(CSV_LOG, "r"):
            file_exists = True
    except FileNotFoundError:
        pass

    try:
        with open(CSV_LOG, "a", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                print("[DEBUG] Creating new CSV file and writing headers.")
                writer.writeheader()
            row = {"timestamp": timestamp, "iface": iface}
            row.update(stats)
            writer.writerow(row)
            print(f"[DEBUG] Wrote stats for {iface} to CSV at {timestamp}")
    except Exception as e:
        print(f"[ERROR] Failed to write to CSV: {e}")

# === Sniffer Thread ===
def sniff_packets(iface):
    print(f"[*] Starting passive packet sniffer on {iface}...")
    sniff(prn=process_packet, store=False, iface=iface)

# === Main Loop ===
if __name__ == "__main__":
    print("[*] QoS Controller started.")
    print(f"[*] Adaptive mode is {'ON' if ADAPTIVE_MODE else 'OFF'}.")

    for iface in INTERFACES:
        Thread(target=sniff_packets, args=(iface,), daemon=True).start()

    while True:
        for iface in INTERFACES:
            stats = parse_cake_stats(iface)
            ts = datetime.now().isoformat()
            adapt_qos_policy(iface, stats)
            write_metrics_to_csv(ts, iface, stats)
        time.sleep(MONITOR_INTERVAL)