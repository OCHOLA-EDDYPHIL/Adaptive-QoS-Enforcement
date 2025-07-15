import os
import pandas as pd
from feature_extractor import extract_bidirectional_features

def process_pcap_folder(root_folder, output_csv):
    total_files = 0
    total_flows = 0
    intermediate_files = []

    # Iterate over each label directory.
    for label in os.listdir(root_folder):
        label_dir = os.path.join(root_folder, label)
        if not os.path.isdir(label_dir):
            continue

        print(f"[+] Processing label: {label}")
        # Process each pcap/pcapng file in the directory.
        for fname in os.listdir(label_dir):
            if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
                continue

            pcap_path = os.path.join(label_dir, fname)
            print(f"  └─ {fname}... ", end="")
            try:
                df = extract_bidirectional_features(pcap_path, label)
                num_flows = len(df)
                # Write intermediate CSV to avoid keeping all data in memory.
                temp_csv = f"temp_{label}_{fname}.csv"
                df.to_csv(temp_csv, index=False)
                intermediate_files.append(temp_csv)

                total_files += 1
                total_flows += num_flows
                print(f"{num_flows} flows extracted.")
            except Exception as e:
                print(f"[ERROR] {fname}: {e}")

    if intermediate_files:
        # Merge intermediate CSVs using a streaming approach.
        with open(output_csv, "w") as fout:
            header_written = False
            for temp_file in intermediate_files:
                with open(temp_file, "r") as fin:
                    header = next(fin)
                    if not header_written:
                        fout.write(header)
                        header_written = True
                    for line in fin:
                        fout.write(line)

        print(f"\n✅ Done. Processed {total_files} files.")
        print(f"📝 Total flows: {total_flows}")
        print(f"📦 Output saved to: {output_csv}")

        # Optionally, delete intermediate files.
        for temp_file in intermediate_files:
            try:
                os.remove(temp_file)
            except Exception as e:
                print(f"[WARNING] Could not delete {temp_file}: {e}")
    else:
        print("⚠️ No flows were extracted.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Process pcap files and extract flows to a combined CSV file."
    )
    parser.add_argument("pcap_root", help="Root folder containing voip/video/bulk subfolders")
    parser.add_argument("output_csv", help="Output CSV filename")
    args = parser.parse_args()

    process_pcap_folder(args.pcap_root, args.output_csv)