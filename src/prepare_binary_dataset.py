
from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/raw/extracted/CSV")
OUTPUT_DIR = Path("data/processed")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FILES = [
    (DATA_DIR / "Benign_Final" / "BenignTraffic.pcap.csv", 0),
    (DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood15.pcap.csv", 1),
]

frames = []

for file_path, label in FILES:
    print(f"\nReading: {file_path}")

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Load one file at a time to limit peak memory usage.
    df = pd.read_csv(file_path, low_memory=False)

    print(f"Rows loaded: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    # Validate numeric feature data.
    df["Label"] = label
    frames.append(df)

    print(f"Assigned label: {label}")

dataset = pd.concat(frames, ignore_index=True)

# Shuffle rows reproducibly so the classes are mixed.
dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)

output_path = OUTPUT_DIR / "binary_iot_dataset.csv"
dataset.to_csv(output_path, index=False)

print("\nDataset preparation complete.")
print(f"Output: {output_path}")
print(f"Total rows: {len(dataset):,}")
print(f"Total columns: {len(dataset.columns)}")
print("\nClass distribution:")
print(dataset["Label"].value_counts().sort_index())
print("\nSaved size: {:.2f} MB".format(output_path.stat().st_size / (1024**2)))
