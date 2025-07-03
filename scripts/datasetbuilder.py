import os
import pandas as pd
from feature_extractor import extract_bidirectional_features

def process_pcap_folder(root_folder, output_csv):
    all_rows = []
    total_files = 0

    for label in os.listdir(root_folder):
        label_dir = os.path.join(root_folder, label)
        if not os.path.isdir(label_dir):
            continue

        print(f"[+] Processing label: {label}")
        for fname in os.listdir(label_dir):
            if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
                continue

            pcap_path = os.path.join(label_dir, fname)
            print(f"  └─ {fname}... ", end="")
            try:
                df = extract_bidirectional_features(pcap_path, label)
                all_rows.append(df)
                total_files += 1
                print(f"{len(df)} flows extracted.")
            except Exception as e:
                print(f"[ERROR] {fname}: {e}")

    if all_rows:
        combined = pd.concat(all_rows, ignore_index=True)
        combined.to_csv(output_csv, index=False)
        print(f"\n✅ Done. Processed {total_files} files.")
        print(f"📝 Total flows: {len(combined)}")
        print(f"📦 Output saved to: {output_csv}")
    else:
        print("⚠️ No flows were extracted.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_root", help="Root folder containing voip/video/bulk subfolders")
    parser.add_argument("output_csv", help="Output CSV filename")
    args = parser.parse_args()

    process_pcap_folder(args.pcap_root, args.output_csv)
