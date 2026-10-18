
from pathlib import Path
import numpy as np
import pandas as pd

INPUT_FILE = Path("data/processed/binary_iot_dataset.csv")
OUTPUT_FILE = Path("data/processed/clean_iot_dataset.csv")

print("Loading dataset...")
df = pd.read_csv(INPUT_FILE, low_memory=False)

print("Original shape:", df.shape)

# Remove features that have no variation.
constant_features = ["Telnet", "SMTP"]
df = df.drop(columns=constant_features, errors="raise")
print("Removed constant features:", constant_features)

# Convert infinite values to missing values.
feature_columns = [c for c in df.columns if c != "Label"]
df[feature_columns] = df[feature_columns].replace(
    [np.inf, -np.inf], np.nan
)

missing_rows = int(df[feature_columns].isna().any(axis=1).sum())
print("Rows containing missing/non-finite features:", missing_rows)

# Remove incomplete rows for this baseline experiment.
before_missing = len(df)
df = df.dropna(subset=feature_columns).copy()
print("Rows removed for missing/non-finite values:",
      before_missing - len(df))

# Verify labels before removing duplicate feature patterns.
if not set(df["Label"].unique()).issubset({0, 1}):
    raise ValueError("Unexpected label values found.")

# Identical feature vectors with different labels would be ambiguous.
conflicting = (
    df.groupby(feature_columns, dropna=False)["Label"]
      .nunique()
      .gt(1)
)

if conflicting.any():
    raise ValueError(
        "Identical feature vectors have conflicting labels. "
        "Investigate before deduplication."
    )

# Remove repeated feature vectors, retaining one observation per pattern.
before_duplicates = len(df)
df = df.drop_duplicates(subset=feature_columns, keep="first")
removed_duplicates = before_duplicates - len(df)

# Save the cleaned dataset.
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print("\nCLEANING SUMMARY")
print("Rows before cleaning: 627,518")
print("Rows after cleaning:", f"{len(df):,}")
print("Duplicate feature rows removed:", f"{removed_duplicates:,}")
print("Columns after removing constants:", len(df.columns))
print("Remaining missing values:", int(df.isna().sum().sum()))
print("\nClass distribution:")
print(df["Label"].value_counts().sort_index())
print("\nSaved to:", OUTPUT_FILE)
print("Saved size: {:.2f} MB".format(
    OUTPUT_FILE.stat().st_size / (1024**2)
))
