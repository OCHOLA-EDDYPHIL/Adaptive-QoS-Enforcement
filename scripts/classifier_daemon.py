from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import joblib
import time
import pandas as pd
import subprocess
from threading import Thread

# === Load classifier and encoders ===
model_path = "/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti/models/dtree_model2.pkl"
model = joblib.load(model_path)
label_encoder = joblib.load(model_path.replace(".pkl", "_labels.pkl"))
proto_encoder = joblib.load(model_path.replace(".pkl", "_proto.pkl"))
feature_order = joblib.load(model_path.replace(".pkl", "_features.pkl"))

# === Flow state ===
flow_table = defaultdict(lambda: {'fwd': [], 'bwd': [], 'start': None})

# DSCP mappings
DSCP_MAP = {
    'voip': 46,  # Expedited Forwarding
    'video': 40,  # CS5
    'bulk': 8,   # CS1
    'unknown': 0  # Best-effort
}

# Add these helper functions near the top of your file

def is_flow_classified(src_ip, dst_ip):
    """
    Check if the flow has already been classified. The comparison is order-insensitive.
    """
    try:
        with open("classified_flows.csv", "r") as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    logged_src, logged_dst = parts[0:2]
                    if {logged_src, logged_dst} == {src_ip, dst_ip}:
                        return True
    except FileNotFoundError:
        # If the file doesn't exist, no flow has been classified yet.
        return False
    return False

def rule_exists(src, dst, dscp):
    """
    Check if an iptables rule already exists.
    Returns True if the rule exists, else False.
    """
    cmd = [
        "iptables", "-t", "mangle", "-C", "PREROUTING",
        "-s", src, "-d", dst,
        "-j", "DSCP", "--set-dscp", str(dscp)
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def canonical_key(ip1, ip2, port1, port2, proto):
    return tuple(sorted([(ip1, port1), (ip2, port2)]) + [proto])

def packet_handler(pkt):
    try:
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

        if len(flow['fwd']) + len(flow['bwd']) >= 20:
            classify_flow(key, ip.src, ip.dst)

    except Exception as e:
        print(f"[!] Error handling packet: {e}")

def classify_flow(key, src_ip, dst_ip):
    # Prevent duplicate classification based on the CSV log
    if is_flow_classified(src_ip, dst_ip):
        print(f"[~] Flow {src_ip} → {dst_ip} already classified, skipping.")
        del flow_table[key]
        return

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

    # Extract ports from key
    (ip1, port1), (ip2, port2), proto = key
    src_port = port1 if src_ip == ip1 else port2
    dst_port = port2 if dst_ip == ip2 else port1

    try:
        row = {
            "src_port":      src_port,
            "dst_port":      dst_port,
            "TotFwdPkts":    fwd_count,
            "TotBwdPkts":    bwd_count,
            "TotLenFwdPkts": fwd_bytes,
            "TotLenBwdPkts": bwd_bytes,
            "FwdPktLenMean": fwd_avg_size,
            "BwdPktLenMean": bwd_avg_size,
            "FwdIATMean":    fwd_iat,
            "BwdIATMean":    bwd_iat,
            "FlowDuration":  duration,
            "FlowByts/s":    (fwd_bytes + bwd_bytes) / duration,
            "FlowPkts/s":    (fwd_count + bwd_count) / duration,
            "protocol":      proto_encoder.transform([proto])[0]
        }

        df = pd.DataFrame([row])
        df = df[feature_order]  # enforce exact order
        print("[DEBUG] Feature row:\n", df)

        proba = model.predict_proba(df)[0]
        confidence = max(proba)
        class_idx = proba.argmax()
        label = label_encoder.inverse_transform([class_idx])[0]

        if confidence < 0.6:
            label = "unknown"

        dscp = DSCP_MAP[label]
        print(f"[+] Flow {src_ip} → {dst_ip} classified as {label} (conf={confidence:.2f}) → DSCP {dscp}")

        for s, d in [(src_ip, dst_ip), (dst_ip, src_ip)]:
            # Safeguard: Append iptables rule only if it doesn't present
            if not rule_exists(s, d, dscp):
                cmd = [
                    "iptables", "-t", "mangle", "-A", "PREROUTING",
                    "-s", s, "-d", d,
                    "-j", "DSCP", "--set-dscp", str(dscp)
                ]
                subprocess.run(cmd)
                print(f"[+] iptables rule added: {' '.join(cmd)}")
            else:
                print(f"[~] iptables rule already exists for {s} → {d} with DSCP {dscp}")

        # Log the classified flow for future duplicate avoidance
        with open("classified_flows.csv", "a") as log:
            log.write(f"{src_ip},{dst_ip},{label},{confidence:.2f}\n")

    except Exception as e:
        print(f"[!] Classification error: {e}")

    # Remove the flow from the table no matter the result.
    del flow_table[key]

def sniff_on(iface):
    print(f"[*] Sniffing on {iface}...")
    sniff(prn=packet_handler, store=False, iface=iface)

if __name__ == "__main__":
    print("[*] Starting real-time QoS classifier daemon...")
    interfaces = ["r1-eth0", "r1-eth1", "r1-eth2"]

    for iface in interfaces:
        Thread(target=sniff_on, args=(iface,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Stopping classifier.")
