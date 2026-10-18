
from pathlib import Path
import numpy as np
import pandas as pd

FILE_PATH = Path("data/processed/binary_iot_dataset.csv")
CHUNK_SIZE = 50_000

if not FILE_PATH.exists():
    raise FileNotFoundError(FILE_PATH)

# Read only the header first.
columns = pd.read_csv(FILE_PATH, nrows=0).columns.tolist()
features = [col for col in columns if col != "Label"]

print("=" * 65)
print("DATA QUALITY REPORT")
print("=" * 65)
print("Columns:", len(columns))
print("Features:", len(features))

missing = {col: 0 for col in columns}
infinite = {col: 0 for col in columns}
negative = {col: 0 for col in features}
non_numeric = {col: 0 for col in features}
constant_values = {}
minimum = {col: np.inf for col in features}
maximum = {col: -np.inf for col in features}
row_count = 0

for chunk in pd.read_csv(FILE_PATH, chunksize=CHUNK_SIZE):
    row_count += len(chunk)

    for col in columns:
        missing[col] += int(chunk[col].isna().sum())

    for col in features:
        values = pd.to_numeric(chunk[col], errors="coerce")

        # Values that were present but could not be parsed as numbers.
        non_numeric[col] += int(
            (chunk[col].notna() & values.isna()).sum()
        )

        # Count positive and negative infinity separately as one total.
        array = values.to_numpy(dtype=float, na_value=np.nan)
        infinite[col] += int(np.isinf(array).sum())

        finite = array[np.isfinite(array)]

        if finite.size:
            minimum[col] = min(minimum[col], float(finite.min()))
            maximum[col] = max(maximum[col], float(finite.max()))
            negative[col] += int((finite < 0).sum())

print("\nTotal rows inspected:", f"{row_count:,}")

print("\nMissing values by column:")
for col, count in missing.items():
    if count:
        print(f"  {col}: {count:,}")

print("\nInfinite values by column:")
found_inf = False
for col, count in infinite.items():
    if count:
        print(f"  {col}: {count:,}")
        found_inf = True
if not found_inf:
    print("  None")

print("\nUnexpected non-numeric feature values:")
found_non_numeric = False
for col, count in non_numeric.items():
    if count:
        print(f"  {col}: {count:,}")
        found_non_numeric = True
if not found_non_numeric:
    print("  None")

print("\nNegative values by feature:")
found_negative = False
for col, count in negative.items():
    if count:
        print(f"  {col}: {count:,}")
        found_negative = True
if not found_negative:
    print("  None")

print("\nFeature ranges:")
for col in features:
    low = minimum[col]
    high = maximum[col]

    if np.isfinite(low) and np.isfinite(high):
        print(f"  {col}: min={low:.6g}, max={high:.6g}")
    else:
        print(f"  {col}: no finite numeric values")

print("\nInspection complete. Original dataset unchanged.")
