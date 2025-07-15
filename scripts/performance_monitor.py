import time
import csv
from datetime import datetime
from scapy.all import sniff, IP, UDP, TCP
from collections import defaultdict, deque
from threading import Thread, Lock

# === Settings ===
INTERFACE = "r1-eth0"  # Single router interface due to Mininet switch
OUTPUT_CSV = "performance_metrics.csv"
SAMPLING_INTERVAL = 1  # seconds
WINDOW_SIZE = 10  # number of recent packets to compute jitter

# === Flow state ===
flow_stats = defaultdict(lambda: {
    'last_arrival': None,
    'iat_deque': deque(maxlen=WINDOW_SIZE),
    'pkt_count': 0,
    'byte_count': 0
})

flow_lock = Lock()

# === Helpers ===
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = 'UDP' if UDP in pkt else 'TCP' if TCP in pkt else 'OTHER'
    if proto not in ('UDP', 'TCP'):
        return None
    l4 = pkt[UDP] if proto == 'UDP' else pkt[TCP]
    return (ip.src, ip.dst, l4.sport, l4.dport, proto)

def packet_handler(pkt):
    key = get_flow_key(pkt)
    if not key:
        return

    with flow_lock:
        flow = flow_stats[key]
        now = pkt.time

        # Compute inter-arrival time (IAT) and jitter
        if flow['last_arrival']:
            iat = now - flow['last_arrival']
            flow['iat_deque'].append(iat)
        flow['last_arrival'] = now

        # Update traffic volume
        flow['pkt_count'] += 1
        flow['byte_count'] += len(pkt)

def monitor_metrics():
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "flow", "latency_ms", "jitter_ms", "bandwidth_kbps", "packet_loss_pct"
        ])

        while True:
            time.sleep(SAMPLING_INTERVAL)
            timestamp = datetime.now().isoformat()

            with flow_lock:
                for key, stats in list(flow_stats.items()):
                    src, dst, sport, dport, proto = key
                    flow_id = f"{src}:{sport}->{dst}:{dport} ({proto})"

                    # Estimate latency as last observed inter-arrival time (not ideal, but passive)
                    latency = stats['iat_deque'][-1] if stats['iat_deque'] else 0
                    # Jitter as standard deviation of IAT
                    jitter = (sum((x - (sum(stats['iat_deque'])/len(stats['iat_deque'])))**2 for x in stats['iat_deque']) / len(stats['iat_deque']))**0.5 if stats['iat_deque'] else 0
                    # Bandwidth in kbps
                    bandwidth = (stats['byte_count'] * 8) / 1000 / SAMPLING_INTERVAL
                    # Passive estimation: assume no packet loss unless we track expected counts (requires active monitoring)
                    pkt_loss_pct = 0.0

                    writer.writerow([
                        timestamp,
                        flow_id,
                        round(latency * 1000, 2),  # ms
                        round(jitter * 1000, 2),   # ms
                        round(bandwidth, 2),       # kbps
                        pkt_loss_pct
                    ])

                f.flush()

if __name__ == "__main__":
    print(f"[*] Passive performance monitor started on {INTERFACE}...")
    Thread(target=monitor_metrics, daemon=True).start()
    sniff(iface=INTERFACE, prn=packet_handler, store=False)
