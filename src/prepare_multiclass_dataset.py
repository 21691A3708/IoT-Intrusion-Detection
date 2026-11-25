from pathlib import Path
import json
import hashlib
import time

import numpy as np
import pandas as pd

from multiclass_label_mapping import ID_TO_LABEL


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "raw" / "extracted" / "CSV"
)

OUTPUT_DIR = (
    PROJECT_ROOT / "data" / "processed" / "multiclass"
)

RESULTS_DIR = PROJECT_ROOT / "results" / "multiclass"

MANIFEST_PATH = RESULTS_DIR / "capture_split.csv"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# Memory-efficient development settings.
CHUNK_SIZE = 50_000

MAX_ROWS_PER_CAPTURE = 5_000

RANDOM_STATE = 42


# Same 36 features used by the existing backend.
EXPECTED_FEATURES = [
    "Header_Length",
    "Protocol Type",
    "Time_To_Live",
    "Rate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IGMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Variance",
]


def process_capture(file_path, record):

    # Reproducible but different seed for each capture.
    capture_hash = hashlib.sha256(
        record["SourceCapture"].encode("utf-8")
    ).digest()

    seed = (
        RANDOM_STATE
        + int.from_bytes(capture_hash[:4], "little")
    )

    rng = np.random.default_rng(seed)

    sampled = pd.DataFrame()

    total_rows = 0

    valid_rows = 0

    header = pd.read_csv(
        file_path,
        nrows=0,
    ).columns.tolist()

    missing = [
        col for col in EXPECTED_FEATURES
        if col not in header
    ]

    if missing:
        raise ValueError(
            f"Missing features in {file_path}: {missing}"
        )

    for chunk in pd.read_csv(
        file_path,
        usecols=EXPECTED_FEATURES,
        chunksize=CHUNK_SIZE,
    ):

        total_rows += len(chunk)

        # Enforce numeric features.
        chunk = chunk[EXPECTED_FEATURES].apply(
            pd.to_numeric,
            errors="coerce",
        )

        # Remove missing and infinite values.
        chunk = chunk.replace(
            [np.inf, -np.inf],
            np.nan,
        )

        chunk = chunk.dropna()

        # Reduce memory consumption.
        chunk = chunk.astype("float32")

        # Reject values that overflowed during conversion.
        finite_mask = np.isfinite(
            chunk.to_numpy()
        ).all(axis=1)

        chunk = chunk.loc[finite_mask].copy()

        valid_rows += len(chunk)

        if chunk.empty:
            continue

        # Assign random sampling priorities.
        chunk["_priority"] = rng.random(len(chunk))

        # Keep only the lowest random priorities.
        # This samples across the entire capture.
        sampled = pd.concat(
            [sampled, chunk],
            ignore_index=True,
        )

        sampled = sampled.nsmallest(
            MAX_ROWS_PER_CAPTURE,
            "_priority",
        )

    if sampled.empty:
        raise ValueError(
            f"No valid records in {file_path}"
        )

    sampled = sampled.drop(
        columns=["_priority"]
    )

    sampled = sampled.drop_duplicates(
        subset=EXPECTED_FEATURES
    ).reset_index(drop=True)

    sampled["Label"] = int(record["Label"])

    sampled["AttackFamily"] = record["AttackFamily"]

    sampled["OriginalAttack"] = record["OriginalAttack"]

    sampled["SourceCapture"] = record["SourceCapture"]

    stats = {
        "SourceCapture": record["SourceCapture"],
        "AttackFamily": record["AttackFamily"],
        "Split": record["Split"],
        "OriginalRows": total_rows,
        "ValidRows": valid_rows,
        "InvalidRows": total_rows - valid_rows,
        "SampledRows": len(sampled),
    }

    return sampled, stats


def main():

    start = time.perf_counter()

    if not MANIFEST_PATH.is_file():
        raise FileNotFoundError(
            "Run multiclass_capture_split.py first."
        )

    manifest = pd.read_csv(MANIFEST_PATH)

    if manifest["RelativePath"].duplicated().any():
        raise ValueError(
            "Duplicate capture in split manifest."
        )

    all_stats = []

    print("=" * 70)
    print("MULTICLASS DATASET PREPARATION")
    print("=" * 70)

    print("Total captures:", len(manifest))

    print("Features:", len(EXPECTED_FEATURES))

    print("Chunk size:", CHUNK_SIZE)

    print("Max rows per capture:", MAX_ROWS_PER_CAPTURE)

    for split_name in ["train", "validation", "test"]:

        split_manifest = manifest[
            manifest["Split"] == split_name
        ]

        output_path = (
            OUTPUT_DIR / f"{split_name}.csv"
        )

        temporary_path = (
            OUTPUT_DIR / f"{split_name}.tmp.csv"
        )

        total_saved = 0

        write_header = True

        print("\n" + "=" * 70)

        print("PROCESSING:", split_name.upper())

        print("=" * 70)

        records = split_manifest.to_dict(
            orient="records"
        )

        for index, record in enumerate(
            records, start=1
        ):

            file_path = (
                DATA_DIR / record["RelativePath"]
            )

            sampled, stats = process_capture(
                file_path,
                record,
            )

            sampled.to_csv(
                temporary_path,
                mode="w" if write_header else "a",
                header=write_header,
                index=False,
            )

            write_header = False

            total_saved += len(sampled)

            all_stats.append(stats)

            print(
                f"[{index}/{len(records)}] "
                f"{record['AttackFamily']:<16} "
                f"{file_path.name:<35} "
                f"Saved: {len(sampled):,}"
            )

        if write_header:
            raise ValueError(
                f"No records written for {split_name}"
            )

        # Replace the final output only after
        # the complete partition is processed.
        temporary_path.replace(output_path)

        print(
            f"\n{split_name.upper()} "
            f"rows saved: {total_saved:,}"
        )

        print("Output:", output_path)

    stats_df = pd.DataFrame(all_stats)

    stats_df.to_csv(
        RESULTS_DIR / "preprocessing_statistics.csv",
        index=False,
    )

    summary = stats_df.pivot_table(
        index="AttackFamily",
        columns="Split",
        values="SampledRows",
        aggfunc="sum",
        fill_value=0,
    )

    summary = summary.reindex(
        index=list(ID_TO_LABEL.values()),
        columns=["train", "validation", "test"],
        fill_value=0,
    )

    summary["Total"] = summary.sum(axis=1)

    summary.to_csv(
        RESULTS_DIR / "dataset_summary.csv"
    )

    with open(
        OUTPUT_DIR / "feature_schema.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            EXPECTED_FEATURES,
            file,
            indent=4,
        )

    with open(
        OUTPUT_DIR / "label_mapping.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            ID_TO_LABEL,
            file,
            indent=4,
        )

    elapsed = time.perf_counter() - start

    print("\n" + "=" * 70)

    print("FINAL DATASET SUMMARY")

    print("=" * 70)

    print(summary.to_string())

    print(
        "\nTotal original rows:",
        f"{stats_df['OriginalRows'].sum():,}",
    )

    print(
        "Total invalid rows removed:",
        f"{stats_df['InvalidRows'].sum():,}",
    )

    print(
        "Total sampled rows:",
        f"{stats_df['SampledRows'].sum():,}",
    )

    print(
        f"Processing time: {elapsed / 60:.2f} minutes"
    )

    print("\nDataset preparation completed.")


if __name__ == "__main__":
    main()