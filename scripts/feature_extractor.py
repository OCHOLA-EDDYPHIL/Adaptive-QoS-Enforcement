from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from collections import defaultdict
from tqdm import tqdm


def canonical_key(src_ip, dst_ip, sport, dport, proto):
    """Create a flow key that treats A→B and B→A as the same flow."""
    if (src_ip, sport) <= (dst_ip, dport):
        return (src_ip, dst_ip, sport, dport, proto)
    else:
        return (dst_ip, src_ip, dport, sport, proto)


def extract_bidirectional_features(pcap_file, label):
    packets = rdpcap(pcap_file)
    flows = defaultdict(lambda: {'fwd': [], 'bwd': []})

    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            proto = 'TCP' if TCP in pkt else 'UDP'
            ip = pkt[IP]
            trans = pkt[TCP] if TCP in pkt else pkt[UDP]

            key = canonical_key(ip.src, ip.dst, trans.sport, trans.dport, proto)
            direction = 'fwd' if (ip.src, trans.sport) <= (ip.dst, trans.dport) else 'bwd'
            flows[key][direction].append((pkt.time, len(pkt)))

    rows = []
    for key, dirs in flows.items():
        fwd = dirs['fwd']
        bwd = dirs['bwd']
        all_times = [t for t, _ in fwd + bwd]
        if len(all_times) < 2:
            continue

        flow_duration = max(all_times) - min(all_times)

        def stats(pkt_list):
            if not pkt_list:
                return (0, 0, 0, 0)
            times, sizes = zip(*pkt_list)
            iats = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
            return (
                len(sizes),
                sum(sizes),
                sum(sizes) / len(sizes),
                sum(iats) / len(iats) if iats else 0
            )

        fwd_count, fwd_bytes, fwd_avg_size, fwd_iat = stats(fwd)
        bwd_count, bwd_bytes, bwd_avg_size, bwd_iat = stats(bwd)

        total_packets = fwd_count + bwd_count
        total_bytes = fwd_bytes + bwd_bytes

        row = {
            'src_ip': key[0],
            'dst_ip': key[1],
            'src_port': key[2],
            'dst_port': key[3],
            'protocol': key[4],
            'TotFwdPkts': fwd_count,
            'TotBwdPkts': bwd_count,
            'TotLenFwdPkts': fwd_bytes,
            'TotLenBwdPkts': bwd_bytes,
            'FwdPktLenMean': fwd_avg_size,
            'BwdPktLenMean': bwd_avg_size,
            'FwdIATMean': fwd_iat,
            'BwdIATMean': bwd_iat,
            'FlowDuration': flow_duration,
            'FlowByts/s': total_bytes / flow_duration if flow_duration > 0 else 0,
            'FlowPkts/s': total_packets / flow_duration if flow_duration > 0 else 0,
            'Label': label
        }
        rows.append(row)

    return pd.DataFrame(rows)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to the pcap file")
    parser.add_argument("label", help="Label for this traffic: voip, video, bulk")
    parser.add_argument("--output", default="flow_features.csv", help="Output CSV file")
    args = parser.parse_args()

    print(f"[+] Extracting bidirectional flow features from {args.pcap} (label={args.label})...")
    df = extract_bidirectional_features(args.pcap, args.label)
    df.to_csv(args.output, index=False)
    print(f"[+] Done. Extracted {len(df)} labeled flows → {args.output}")
