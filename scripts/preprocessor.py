import pandas as pd
import argparse

# Map raw device categories to QoS classes
LABEL_MAP = {
    "Audio": "voip",
    "Camera": "video",
    "Hub": "bulk",
    "Sensor": "bulk",
    "TV": "video",
    "Printer": "bulk",
    "Appliance": "bulk",
    "Unknown": "bulk"
}

# Core flow-level features to keep
SELECTED_COLUMNS = [
    "FlowDuration", "TotFwdPkts", "TotBwdPkts",
    "TotLenFwdPkts", "TotLenBwdPkts",
    "FwdPktLenMean", "BwdPktLenMean",
    "FlowByts/s", "FlowPkts/s",
    "FlowIATMean", "FlowIATStd",
    "PktLenMean", "PktLenStd",
    "FwdHeaderLen", "BwdHeaderLen",
    "FwdPkts/s", "BwdPkts/s"
]


def preprocess(input_csv, output_csv):
    df = pd.read_csv(input_csv)

    # Drop flows with missing or invalid values
    df = df.replace([float('inf'), -float('inf')], pd.NA).dropna()

    # Map raw labels to voip/video/bulk
    df["Label"] = df["Type"].map(LABEL_MAP)

    # Drop rows with unknown/missing label
    df = df.dropna(subset=["Label"])

    # Final dataset with features + label
    df_final = df[SELECTED_COLUMNS + ["Label"]]

    df_final.to_csv(output_csv, index=False)
    print(f"[+] Saved {len(df_final)} cleaned rows to: {output_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv", help="Path to UNSW .csv file (e.g., CIC_IoT_Part_1.csv)")
    parser.add_argument("output_csv", help="Path to save processed training file")
    args = parser.parse_args()

    preprocess(args.input_csv, args.output_csv)
