
from pathlib import Path
import pandas as pd

TRAIN_FILE = Path("data/processed/splits/train.csv")
TEST_FILE = Path("data/processed/splits/test.csv")

for name, path in [("TRAIN", TRAIN_FILE), ("TEST", TEST_FILE)]:
    df = pd.read_csv(path, usecols=["Number", "Label"])

    print(f"\n{name} DATA")
    print("Rows:", len(df))
    print("\nNumber statistics by label:")
    print(
        df.groupby("Label")["Number"]
        .agg(["count", "min", "median", "mean", "max", "nunique"])
        .to_string()
    )

    print("\nMost frequent Number values by label:")
    for label, group in df.groupby("Label"):
        print(f"\nLabel {label}:")
        print(
            group["Number"]
            .value_counts(normalize=True)
            .head(10)
            .round(4)
            .to_string()
        )
