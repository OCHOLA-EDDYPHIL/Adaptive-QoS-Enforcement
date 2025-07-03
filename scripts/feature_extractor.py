from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from collections import defaultdict
import os
from tqdm import tqdm

def extract_features(pcap_file, label):
    packets = rdpcap(pcap_file)
    flows = defaultdict(list)

    # Group packets by 5-tuple flow key
    for pkt in packets:
        if IP in pkt:
            proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
            if proto == 'OTHER':
                continue
            ip_layer = pkt[IP]
            transport_layer = pkt[TCP] if TCP in pkt else pkt[UDP]
            flow_key = (
                ip_layer.src, ip_layer.dst,
                transport_layer.sport, transport_layer.dport,
                proto
            )
            timestamp = pkt.time
            size = len(pkt)
            flows[flow_key].append((timestamp, size))

    # Compute flow-level features
    rows = []
    for flow_key, packets in flows.items():
        if len(packets) < 2:
            continue

        timestamps, sizes = zip(*packets)
        duration = max(timestamps) - min(timestamps)
        inter_arrivals = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]

        row = {
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'src_port': flow_key[2],
            'dst_port': flow_key[3],
            'protocol': flow_key[4],
            'packet_count': len(sizes),
            'total_bytes': sum(sizes),
            'avg_pkt_size': sum(sizes) / len(sizes),
            'flow_duration': duration,
            'mean_iat': sum(inter_arrivals) / len(inter_arrivals),
            'max_iat': max(inter_arrivals),
            'min_iat': min(inter_arrivals),
            'label': label  # Add the label here
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    return df

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to the pcap file")
    parser.add_argument("label", help="Label for the traffic: voip, video, bulk")
    parser.add_argument("--output", default="flow_features.csv", help="Output CSV file")
    args = parser.parse_args()

    print(f"[+] Extracting features from {args.pcap} (label={args.label})...")
    df = extract_features(args.pcap, args.label)
    df.to_csv(args.output, index=False)
    print(f"[+] Done. Saved {len(df)} labeled flows to {args.output}")
