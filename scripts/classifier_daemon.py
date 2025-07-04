from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import joblib
import time
import pandas as pd
import subprocess

# Load model and encoders
model = joblib.load("models/dtree_model2.pkl")
label_encoder = joblib.load("models/dtree_model2_labels.pkl")
proto_encoder = joblib.load("models/dtree_model2_proto.pkl")

flow_table = defaultdict(lambda: {'fwd': [], 'bwd': [], 'start': None})

# DSCP mappings
DSCP_MAP = {
    'voip': 46,  # Expedited Forwarding
    'video': 40,  # CS5
    'bulk': 8,  # CS1
    'unknown': 0  # Best-effort
}


def canonical_key(ip1, ip2, port1, port2, proto):
    return tuple(sorted([(ip1, port1), (ip2, port2)]) + [proto])


def packet_handler(pkt):
    if IP not in pkt or not (TCP in pkt or UDP in pkt):
        return

    proto = 'TCP' if TCP in pkt else 'UDP'
    ip = pkt[IP]
    trans = pkt[TCP] if TCP in pkt else pkt[UDP]

    key = canonical_key(ip.src, ip.dst, trans.sport, trans.dport, proto)
    direction = 'fwd' if (ip.src, trans.sport) <= (ip.dst, trans.dport) else 'bwd'

    flow = flow_table[key]
    timestamp = pkt.time
    size = len(pkt)

    if flow['start'] is None:
        flow['start'] = timestamp

    flow[direction].append((timestamp, size))

    # Classify after enough packets
    if len(flow['fwd']) + len(flow['bwd']) >= 20:
        classify_flow(key, ip.src, ip.dst)


def classify_flow(key, src_ip, dst_ip):
    flow = flow_table[key]
    fwd = flow['fwd']
    bwd = flow['bwd']
    duration = max([t for t, _ in fwd + bwd]) - flow['start']
    if duration == 0:
        return

    def stats(packets):
        if not packets:
            return 0, 0, 0, 0
        times, sizes = zip(*packets)
        iats = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        return (
            len(sizes),
            sum(sizes),
            sum(sizes) / len(sizes),
            sum(iats) / len(iats) if iats else 0
        )

    fwd_count, fwd_bytes, fwd_avg_size, fwd_iat = stats(fwd)
    bwd_count, bwd_bytes, bwd_avg_size, bwd_iat = stats(bwd)

    row = {
        "TotFwdPkts": fwd_count,
        "TotBwdPkts": bwd_count,
        "TotLenFwdPkts": fwd_bytes,
        "TotLenBwdPkts": bwd_bytes,
        "FwdPktLenMean": fwd_avg_size,
        "BwdPktLenMean": bwd_avg_size,
        "FwdIATMean": fwd_iat,
        "BwdIATMean": bwd_iat,
        "FlowDuration": duration,
        "FlowByts/s": (fwd_bytes + bwd_bytes) / duration,
        "FlowPkts/s": (fwd_count + bwd_count) / duration,
        "protocol": proto_encoder.transform([key[2]])[0]
    }

    df = pd.DataFrame([row])
    proba = model.predict_proba(df)[0]
    confidence = max(proba)
    class_idx = proba.argmax()
    label = label_encoder.inverse_transform([class_idx])[0]

    if confidence < 0.6:
        label = "unknown"

    dscp = DSCP_MAP[label]
    print(f"[+] Flow {src_ip} → {dst_ip} classified as {label} (conf={confidence:.2f}) → DSCP {dscp}")

    # Apply mark using iptables
    try:
        subprocess.run([
            "iptables", "-t", "mangle", "-A", "PREROUTING",
            "-s", src_ip, "-d", dst_ip,
            "-j", "DSCP", "--set-dscp", str(dscp)
        ], check=True)
    except Exception as e:
        print(f"[!] Failed to set DSCP: {e}")

    # Cleanup
    del flow_table[key]


if __name__ == "__main__":
    print("[*] Starting real-time QoS classifier daemon...")
    sniff(prn=packet_handler, store=False)
