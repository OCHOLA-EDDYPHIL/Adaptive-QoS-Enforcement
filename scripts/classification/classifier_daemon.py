from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import joblib
import time
import pandas as pd
import subprocess
from threading import Lock

# === Load classifier and encoders ===
project_dir = "/home/nyamabites/Desktop/INCEPTION/projectz/pythonprojectz/cnsprojecti"
model_path = f"{project_dir}/models/dtree_model3.pkl"
model = joblib.load(model_path)
label_encoder = joblib.load(model_path.replace(".pkl", "_labels.pkl"))
proto_encoder = joblib.load(model_path.replace(".pkl", "_proto.pkl"))
feature_order = joblib.load(model_path.replace(".pkl", "_features.pkl"))

# === Flow tracking ===
flow_table = defaultdict(lambda: {'fwd': [], 'bwd': [], 'start': None})
classified_flow_keys = set()
flow_lock = Lock()

MIN_PACKETS = 10
MIN_DURATION = 0.5  # seconds

# DSCP mappings
DSCP_MAP = {
    'voip': 46,
    'video': 40,
    'bulk': 8,
    'unknown': 0
}


def get_conntrack_key(pkt):
    if IP not in pkt or not (TCP in pkt or UDP in pkt):
        return None
    proto = 'TCP' if TCP in pkt else 'UDP'
    ip = pkt[IP]
    l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
    return (ip.src, l4.sport, ip.dst, l4.dport, proto)


def rule_exists(src, dst, dscp):
    cmd = ["iptables", "-t", "mangle", "-C", "PREROUTING",
           "-s", src, "-d", dst, "-j", "DSCP", "--set-dscp", str(dscp)]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0


def packet_handler(pkt):
    try:
        key = get_conntrack_key(pkt)
        if key is None:
            return
        rev_key = (key[2], key[3], key[0], key[1], key[4])

        flow_to_classify = None
        with flow_lock:
            active_key = rev_key if rev_key in flow_table else key
            direction = 'bwd' if rev_key in flow_table else 'fwd'

            if active_key in classified_flow_keys:
                return

            flow = flow_table[active_key]
            if flow['start'] is None:
                flow['start'] = pkt.time
            
            flow[direction].append((pkt.time, len(pkt)))

            if len(flow['fwd']) + len(flow['bwd']) >= MIN_PACKETS:
                duration = max(t for t, _ in flow['fwd'] + flow['bwd']) - flow['start']
                if duration >= MIN_DURATION:
                    classified_flow_keys.add(active_key)
                    flow_to_classify = flow_table.pop(active_key)
        
        if flow_to_classify:
            classify_flow(active_key, flow_to_classify)

    except Exception as e:
        print(f"[!] Error in packet_handler: {type(e).__name__}: {e}")


def classify_flow(key, flow):
    fwd, bwd = flow['fwd'], flow['bwd']
    duration = max(t for t, _ in fwd + bwd) - flow['start']
    if duration == 0:
        return

    def stats(pkts):
        if not pkts: return 0, 0, 0, 0
        times, sizes = zip(*pkts)
        iats = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        return len(sizes), sum(sizes), sum(sizes) / len(sizes), sum(iats) / len(iats) if iats else 0

    fwd_cnt, fwd_bytes, fwd_avg, fwd_iat = stats(fwd)
    bwd_cnt, bwd_bytes, bwd_avg, bwd_iat = stats(bwd)
    src_ip, src_port, dst_ip, dst_port, proto = key

    try:
        row = {
            "src_port": src_port, "dst_port": dst_port,
            "TotFwdPkts": fwd_cnt, "TotBwdPkts": bwd_cnt,
            "TotLenFwdPkts": fwd_bytes, "TotLenBwdPkts": bwd_bytes,
            "FwdPktLenMean": fwd_avg, "BwdPktLenMean": bwd_avg,
            "FwdIATMean": fwd_iat, "BwdIATMean": bwd_iat,
            "FlowDuration": duration,
            "FlowByts/s": (fwd_bytes + bwd_bytes) / duration,
            "FlowPkts/s": (fwd_cnt + bwd_cnt) / duration,
            "protocol": proto_encoder.transform([proto])[0]
        }

        df = pd.DataFrame([row])[feature_order]
        print("[DEBUG] Features:\n", df)

        proba = model.predict_proba(df)[0]
        confidence = max(proba)
        label = label_encoder.inverse_transform([proba.argmax()])[0]
        if confidence < 0.6:
            label = "unknown"

        dscp = DSCP_MAP[label]
        print(f"[+] {src_ip}:{src_port} → {dst_ip}:{dst_port} classified as {label} ({confidence:.2f}) → DSCP {dscp}")

        for s, d in [(src_ip, dst_ip), (dst_ip, src_ip)]:
            if not rule_exists(s, d, dscp):
                subprocess.run([
                    "iptables", "-t", "mangle", "-A", "PREROUTING",
                    "-s", s, "-d", d,
                    "-j", "DSCP", "--set-dscp", str(dscp)
                ])

        with open("performance/classified_flows.csv", "a") as log:
            log.write(f"{src_ip},{dst_ip},{label},{confidence:.2f}\n")

    except Exception as e:
        print(f"[!] Classification error: {e}")


if __name__ == "__main__":
    print("[*] QoS classifier daemon starting ...")
    sniff(prn=packet_handler, store=False, iface="r1-eth0")
