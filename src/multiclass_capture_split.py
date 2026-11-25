from pathlib import Path
from collections import defaultdict
import random

import pandas as pd

from multiclass_label_mapping import (
    LABEL_MAPPING,
    get_attack_family,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "raw" / "extracted" / "CSV"
)

RESULTS_DIR = PROJECT_ROOT / "results" / "multiclass"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42


def split_family(files, rng):

    files = sorted(files)

    rng.shuffle(files)

    count = len(files)

    if count == 1:
        return files, [], []

    if count == 2:
        return files[:1], [], files[1:]

    # Ensure at least one file in every partition.
    n_test = max(1, round(count * 0.15))

    n_validation = max(1, round(count * 0.15))

    n_train = count - n_test - n_validation

    train_files = files[:n_train]

    validation_files = files[
        n_train:n_train + n_validation
    ]

    test_files = files[
        n_train + n_validation:
    ]

    return train_files, validation_files, test_files


def main():

    if not DATA_DIR.is_dir():
        raise FileNotFoundError(DATA_DIR)

    csv_files = sorted(DATA_DIR.rglob("*.csv"))

    if not csv_files:
        raise ValueError("No CSV files found.")

    grouped_files = defaultdict(list)

    for file_path in csv_files:

        family = get_attack_family(
            file_path.parent.name
        )

        grouped_files[family].append(file_path)

    rng = random.Random(RANDOM_STATE)

    records = []

    for family, label in LABEL_MAPPING.items():

        files = grouped_files[family]

        if not files:
            raise ValueError(
                f"No files found for {family}"
            )

        train, validation, test = split_family(
            files, rng
        )

        partitions = {
            "train": train,
            "validation": validation,
            "test": test,
        }

        for split_name, split_files in partitions.items():

            for file_path in split_files:

                records.append({
                    "RelativePath": file_path.relative_to(
                        DATA_DIR
                    ).as_posix(),

                    "SourceCapture": file_path.relative_to(
                        DATA_DIR
                    ).as_posix(),

                    "OriginalAttack": file_path.parent.name,

                    "AttackFamily": family,

                    "Label": label,

                    "Split": split_name,
                })

    manifest = pd.DataFrame(records)

    # Every source file must appear exactly once.
    if manifest["RelativePath"].duplicated().any():
        raise ValueError("Duplicate capture allocation.")

    if len(manifest) != len(csv_files):
        raise ValueError("Some captures were not allocated.")

    summary = pd.crosstab(
        manifest["AttackFamily"],
        manifest["Split"],
    ).reindex(
        index=list(LABEL_MAPPING),
        columns=["train", "validation", "test"],
        fill_value=0,
    )

    summary["Total"] = summary.sum(axis=1)

    print("=" * 65)
    print("MULTICLASS CAPTURE SPLIT")
    print("=" * 65)

    print(summary.to_string())

    print("\nTotal files:", len(manifest))

    print("\nPartition totals:")

    print(manifest["Split"].value_counts().to_string())

    for family in LABEL_MAPPING:

        for split in ["validation", "test"]:

            if summary.loc[family, split] == 0:

                print(
                    f"WARNING: {family} has no "
                    f"independent {split} capture."
                )

    output_path = RESULTS_DIR / "capture_split.csv"

    manifest.to_csv(output_path, index=False)

    summary.to_csv(
        RESULTS_DIR / "capture_split_summary.csv"
    )

    print("\nManifest saved:", output_path)

    print("Capture splitting completed.")


if __name__ == "__main__":
    main()