from scapy.all import IP, TCP, UDP
from scapy.utils import PcapReader
from collections import defaultdict
import csv


def canonical_key(src_ip, dst_ip, sport, dport, proto):
    if (src_ip, sport) <= (dst_ip, dport):
        return (src_ip, dst_ip, sport, dport, proto)
    else:
        return (dst_ip, src_ip, dport, sport, proto)


def extract_and_write_flows_streaming(pcap_file, output_csv):
    flows = defaultdict(lambda: {'fwd': [], 'bwd': []})
    flow_keys_written = set()

    # Open the CSV file for writing
    with open(output_csv, "w", newline="") as csvfile:
        fieldnames = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'TotFwdPkts', 'TotBwdPkts', 'TotLenFwdPkts', 'TotLenBwdPkts',
            'FwdPktLenMean', 'BwdPktLenMean', 'FwdIATMean', 'BwdIATMean',
            'FlowDuration', 'FlowByts/s', 'FlowPkts/s'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                if IP in pkt and (TCP in pkt or UDP in pkt):
                    proto = 'TCP' if TCP in pkt else 'UDP'
                    ip = pkt[IP]
                    trans = pkt[TCP] if TCP in pkt else pkt[UDP]

                    key = canonical_key(ip.src, ip.dst, trans.sport, trans.dport, proto)
                    direction = 'fwd' if (ip.src, trans.sport) <= (ip.dst, trans.dport) else 'bwd'
                    flows[key][direction].append((pkt.time, len(pkt)))

                    # Flush flow to CSV if it exceeds a certain packet count (e.g. 50) for RAM control
                    if len(flows[key]['fwd']) + len(flows[key]['bwd']) > 50:
                        write_flow(writer, key, flows.pop(key))

        # Write any remaining flows
        for key, dirs in flows.items():
            write_flow(writer, key, dirs)

def write_flow(writer, key, dirs):
    fwd = dirs['fwd']
    bwd = dirs['bwd']
    all_times = [t for t, _ in fwd + bwd]
    if len(all_times) < 2:
        return

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
        'FlowPkts/s': total_packets / flow_duration if flow_duration > 0 else 0
    }

    writer.writerow(row)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to large pcap file")
    parser.add_argument("--output", default="flow_features.csv", help="Output CSV filename")
    args = parser.parse_args()

    print(f"[+] Processing {args.pcap} and writing to {args.output}...")
    extract_and_write_flows_streaming(args.pcap, args.output)
    print("[+] Done.")
