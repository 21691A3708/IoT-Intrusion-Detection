
from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/raw/extracted/CSV")

files = [
    DATA_DIR / "Benign_Final" / "BenignTraffic1.pcap.csv",
    DATA_DIR / "Benign_Final" / "BenignTraffic2.pcap.csv",
    DATA_DIR / "Benign_Final" / "BenignTraffic3.pcap.csv",
    DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood.pcap.csv",
    DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood1.pcap.csv",
    DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood2.pcap.csv",
]

reference_file = (
    DATA_DIR / "Benign_Final" / "BenignTraffic.pcap.csv"
)

reference_columns = list(
    pd.read_csv(reference_file, nrows=5).columns
)

print("Reference feature count:", len(reference_columns))
print("\nInspecting other captures...\n")

for file in files:
    print("=" * 65)
    print(file.name)

    if not file.exists():
        print("FILE NOT FOUND")
        continue

    sample = pd.read_csv(file, nrows=5)
    columns = list(sample.columns)

    print("File size (MB):", round(file.stat().st_size / (1024 * 1024), 2))
    print("Feature count:", len(columns))
    print("Same column names and order:", columns == reference_columns)

    if columns != reference_columns:
        print("Missing columns:", sorted(set(reference_columns) - set(columns)))
        print("Extra columns:", sorted(set(columns) - set(reference_columns)))

    non_numeric = [
        col for col in sample.columns
        if not pd.api.types.is_numeric_dtype(sample[col])
    ]
    print("Non-numeric columns in sample:", non_numeric)

print("\nSchema inspection completed.")
