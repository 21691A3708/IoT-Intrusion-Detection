
from pathlib import Path
import pandas as pd

FILE_PATH = Path("data/processed/binary_iot_dataset.csv")
CHUNK_SIZE = 50_000

if not FILE_PATH.exists():
    raise FileNotFoundError(FILE_PATH)

columns = pd.read_csv(FILE_PATH, nrows=0).columns.tolist()
features = [c for c in columns if c != "Label"]

# Exact row hashes and feature-only hashes.
seen_rows = set()
feature_labels = {}
duplicate_rows = 0
cross_label_duplicates = 0
unique_values = {c: set() for c in features}
row_count = 0

for chunk in pd.read_csv(FILE_PATH, chunksize=CHUNK_SIZE):
    row_count += len(chunk)

    # Count duplicate complete records, including their labels.
    row_hashes = pd.util.hash_pandas_object(
        chunk, index=False
    ).to_numpy()

    for value in row_hashes:
        h = int(value)
        if h in seen_rows:
            duplicate_rows += 1
        else:
            seen_rows.add(h)

    # Check whether identical features ever have different labels.
    feature_hashes = pd.util.hash_pandas_object(
        chunk[features], index=False
    ).to_numpy()

    for h, label in zip(feature_hashes, chunk["Label"]):
        key = int(h)
        label = int(label)

        if key in feature_labels:
            if feature_labels[key] != label:
                cross_label_duplicates += 1
        else:
            feature_labels[key] = label

    # Collect observed values to identify constant features.
    for col in features:
        unique_values[col].update(chunk[col].dropna().unique().tolist())

print("=" * 60)
print("DUPLICATE AND CONSTANT-FEATURE REPORT")
print("=" * 60)
print("Rows checked:", f"{row_count:,}")
print("Repeated complete rows:", f"{duplicate_rows:,}")
print("Repeated feature patterns with conflicting labels:",
      f"{cross_label_duplicates:,}")

constant_features = [
    col for col, values in unique_values.items()
    if len(values) <= 1
]

print("\nConstant features:")
print(constant_features if constant_features else "None")

print("\nNumber of observed unique values per feature:")
for col, values in unique_values.items():
    print(f"{col}: {len(values):,}")

print("\nCheck complete.")
