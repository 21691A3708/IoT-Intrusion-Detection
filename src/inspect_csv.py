
from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/raw/extracted")

files_to_check = [
    "BenignTraffic.pcap.csv",
    "DoS-UDP_Flood15.pcap.csv",
]

for filename in files_to_check:
    matches = list(DATA_DIR.rglob(filename))

    print("\n" + "=" * 60)
    print(f"File: {filename}")

    if not matches:
        print("ERROR: File not found.")
        continue

    file_path = matches[0]
    print(f"Path: {file_path}")
    print(f"Size: {file_path.stat().st_size / (1024**2):.2f} MB")

    try:
        # Read only five rows; do not load the entire dataset.
        sample = pd.read_csv(file_path, nrows=5)

        print(f"Number of columns: {len(sample.columns)}")
        print("Column names:")
        print(sample.columns.tolist())

        label_columns = [
            col for col in sample.columns
            if any(word in col.lower()
                   for word in ["label", "class", "attack", "target"])
        ]

        print("Possible label columns:", label_columns)

        for col in label_columns:
            print(f"Sample values in {col}:")
            print(sample[col].tolist())

    except Exception as exc:
        print(f"ERROR reading file: {exc}")
