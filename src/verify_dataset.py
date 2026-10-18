
from pathlib import Path
from collections import Counter
import pandas as pd

file_path = Path("data/processed/binary_iot_dataset.csv")

if not file_path.exists():
    raise FileNotFoundError(f"Dataset not found: {file_path}")

print("Dataset:", file_path)
print(f"File size: {file_path.stat().st_size / (1024**2):.2f} MB")

# Read only the header first.
columns = pd.read_csv(file_path, nrows=0).columns.tolist()

print("\nNumber of columns:", len(columns))
print("Label column exists:", "Label" in columns)

if "Label" not in columns:
    raise ValueError("Label column is missing.")

row_count = 0
label_counts = Counter()
missing_counts = Counter()
invalid_labels = Counter()

# Process the CSV incrementally to limit RAM usage.
for chunk in pd.read_csv(file_path, chunksize=50_000):
    row_count += len(chunk)

    label_counts.update(chunk["Label"].value_counts().to_dict())
    missing_counts.update(chunk.isna().sum().to_dict())

    invalid = chunk.loc[~chunk["Label"].isin([0, 1]), "Label"]
    invalid_labels.update(invalid.value_counts().to_dict())

print("\nTotal rows:", f"{row_count:,}")
print("Total columns:", len(columns))

print("\nClass distribution:")
for label in sorted(label_counts):
    print(f"Label {label}: {label_counts[label]:,}")

print("\nMissing values:")
missing_total = sum(missing_counts.values())
print("Total missing cells:", f"{missing_total:,}")

if missing_total:
    print("Columns with missing values:")
    for col, count in missing_counts.items():
        if count:
            print(f"  {col}: {count:,}")

print("\nInvalid labels:", dict(invalid_labels))
print("\nVerification finished.")
