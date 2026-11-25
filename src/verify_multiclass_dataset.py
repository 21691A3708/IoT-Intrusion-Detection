from pathlib import Path
import json
import time

import numpy as np
import pandas as pd

from multiclass_label_mapping import ID_TO_LABEL


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "processed" / "multiclass"
)

OUTPUT_DIR = DATA_DIR / "verified"

RESULTS_DIR = PROJECT_ROOT / "results" / "multiclass"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SPLITS = ["train", "validation", "test"]

with open(
    DATA_DIR / "feature_schema.json",
    encoding="utf-8"
) as file:
    FEATURES = json.load(file)


def main():

    start = time.perf_counter()

    seen_hashes = set()
    seen_captures = set()

    reports = []

    print("=" * 70)
    print("MULTICLASS DATASET VERIFICATION")
    print("=" * 70)

    for split in SPLITS:

        print(f"\nChecking {split.upper()} dataset...")

        path = DATA_DIR / f"{split}.csv"

        if not path.is_file():
            raise FileNotFoundError(path)

        df = pd.read_csv(
            path,
            dtype={
                feature: "float32"
                for feature in FEATURES
            },
            float_precision="round_trip",
        )

        original_rows = len(df)

        required_columns = FEATURES + [
            "Label",
            "AttackFamily",
            "OriginalAttack",
            "SourceCapture",
        ]

        missing = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing:
            raise ValueError(
                f"Missing columns: {missing}"
            )

        if not np.isfinite(
            df[FEATURES].to_numpy()
        ).all():
            raise ValueError(
                f"Invalid feature values in {split}"
            )

        if df[required_columns].isna().any().any():
            raise ValueError(
                f"Missing values in {split}"
            )

        if not df["Label"].isin(ID_TO_LABEL).all():
            raise ValueError(
                f"Invalid labels in {split}"
            )

        expected_names = df["Label"].map(ID_TO_LABEL)

        if not expected_names.eq(df["AttackFamily"]).all():
            raise ValueError(
                f"Inconsistent label mapping in {split}"
            )

        # Verify that captures do not overlap.
        captures = set(df["SourceCapture"].unique())

        capture_overlap = captures.intersection(
            seen_captures
        )

        if capture_overlap:
            raise ValueError(
                f"Capture leakage detected: {capture_overlap}"
            )

        seen_captures.update(captures)

        # Normalize signed zeros before hashing.
        features = df[FEATURES].copy()

        features = features.mask(
            features == 0, np.float32(0)
        )

        # Fingerprint only the input features.
        hashes = pd.util.hash_pandas_object(
            features,
            index=False,
        )

        df["_feature_hash"] = hashes

        # Identify identical feature vectors that
        # have different labels within this partition.
        label_counts = df.groupby(
            "_feature_hash"
        )["Label"].nunique()

        conflicting_hashes = label_counts[
            label_counts > 1
        ].index

        conflict_mask = df["_feature_hash"].isin(
            conflicting_hashes
        )

        conflicting_rows = int(conflict_mask.sum())

        df = df.loc[~conflict_mask].copy()

        # Remove repeated feature vectors within
        # the current partition.
        before_deduplication = len(df)

        df = df.drop_duplicates(
            subset=["_feature_hash"]
        ).copy()

        internal_duplicates = (
            before_deduplication - len(df)
        )

        # Remove overlaps with earlier partitions.
        # Priority: train -> validation -> test.
        overlap_mask = df["_feature_hash"].isin(
            seen_hashes
        )

        cross_split_duplicates = int(
            overlap_mask.sum()
        )

        df = df.loc[~overlap_mask].copy()

        seen_hashes.update(
            df["_feature_hash"].tolist()
        )

        df = df.drop(
            columns=["_feature_hash"]
        )

        df = df.reset_index(drop=True)

        if df.empty:
            raise ValueError(
                f"{split} is empty after verification"
            )

        output_path = OUTPUT_DIR / f"{split}.csv"

        df.to_csv(
            output_path,
            index=False,
        )

        report = {
            "Split": split,
            "OriginalRows": original_rows,
            "ConflictingRowsRemoved": conflicting_rows,
            "InternalDuplicatesRemoved": internal_duplicates,
            "CrossSplitDuplicatesRemoved": cross_split_duplicates,
            "FinalRows": len(df),
            "CaptureOverlap": len(capture_overlap),
        }

        reports.append(report)

        print("Original rows:", f"{original_rows:,}")

        print(
            "Conflicting rows removed:",
            f"{conflicting_rows:,}"
        )

        print(
            "Internal duplicates removed:",
            f"{internal_duplicates:,}"
        )

        print(
            "Cross-split duplicates removed:",
            f"{cross_split_duplicates:,}"
        )

        print("Final rows:", f"{len(df):,}")

        print("\nClass distribution:")

        print(
            df["AttackFamily"]
            .value_counts()
            .to_string()
        )

        print("\nSaved:", output_path)

    report_df = pd.DataFrame(reports)

    report_df.to_csv(
        RESULTS_DIR / "verification_report.csv",
        index=False,
    )

    print("\n" + "=" * 70)
    print("FINAL VERIFICATION REPORT")
    print("=" * 70)

    print(report_df.to_string(index=False))

    print(
        "\nTotal verified rows:",
        f"{report_df['FinalRows'].sum():,}"
    )

    print(
        "Verification time:",
        f"{time.perf_counter() - start:.2f} seconds"
    )

    print("\nDataset verification completed.")


if __name__ == "__main__":
    main()