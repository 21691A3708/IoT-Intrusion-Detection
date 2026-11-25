from pathlib import Path
from collections import Counter

import pandas as pd


# Resolve the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data" / "raw" / "extracted" / "CSV"

OUTPUT_DIR = PROJECT_ROOT / "results" / "multiclass"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def get_attack_family(folder_name):
    """Map original CICIoT2023 folders to attack families."""

    name = folder_name.lower().strip()

    if name.startswith("benign"):
        return "Benign"

    if name.startswith("ddos"):
        return "DDoS"

    if name.startswith("dos"):
        return "DoS"

    if name.startswith("recon"):
        return "Reconnaissance"

    if "bruteforce" in name or "brute_force" in name:
        return "BruteForce"

    if "spoofing" in name:
        return "Spoofing"

    if name.startswith("mirai"):
        return "Mirai"

    web_attacks = {
        "browserhijacking",
        "backdoor_malware",
        "xss",
        "uploading_attack",
        "sqlinjection",
        "commandinjection",
    }

    if name in web_attacks or name.startswith("web"):
        return "WebBased"

    return "Unknown"


def main():

    if not DATA_DIR.is_dir():
        raise FileNotFoundError(
            f"Dataset folder not found: {DATA_DIR}"
        )

    csv_files = sorted(DATA_DIR.rglob("*.csv"))

    if not csv_files:
        raise ValueError("No CSV files found.")

    records = []

    family_counts = Counter()

    schema_counts = Counter()

    print("=" * 75)
    print("CICIoT2023 MULTICLASS DATASET INSPECTION")
    print("=" * 75)

    print(f"\nDataset location: {DATA_DIR}")
    print(f"Total CSV files: {len(csv_files)}")

    for file_path in csv_files:

        folder_name = file_path.parent.name

        family = get_attack_family(folder_name)

        size_mb = file_path.stat().st_size / (1024 ** 2)

        try:
            # Read only the header to reduce memory usage.
            columns = pd.read_csv(
                file_path,
                nrows=0
            ).columns.tolist()

            schema = tuple(columns)

            schema_counts[schema] += 1

            records.append({
                "Folder": folder_name,
                "File": file_path.name,
                "RelativePath": str(
                    file_path.relative_to(DATA_DIR)
                ),
                "AttackFamily": family,
                "SizeMB": round(size_mb, 2),
                "ColumnCount": len(columns),
                "Columns": " | ".join(columns),
                "Status": "OK"
            })

            family_counts[family] += 1

        except Exception as error:

            records.append({
                "Folder": folder_name,
                "File": file_path.name,
                "RelativePath": str(
                    file_path.relative_to(DATA_DIR)
                ),
                "AttackFamily": family,
                "SizeMB": round(size_mb, 2),
                "Status": str(error)
            })

    inventory = pd.DataFrame(records)

    valid = inventory[inventory["Status"] == "OK"]

    print("\n" + "=" * 75)
    print("ATTACK FOLDER SUMMARY")
    print("=" * 75)

    if not valid.empty:

        summary = (
            valid.groupby(
                ["AttackFamily", "Folder"]
            )
            .agg(
                CSVFiles=("File", "count"),
                TotalSizeMB=("SizeMB", "sum")
            )
            .reset_index()
        )

        print(summary.to_string(index=False))

    print("\n" + "=" * 75)
    print("ATTACK FAMILY DISTRIBUTION")
    print("=" * 75)

    expected_families = [
        "Benign",
        "DDoS",
        "DoS",
        "Reconnaissance",
        "BruteForce",
        "Spoofing",
        "Mirai",
        "WebBased"
    ]

    for family in expected_families:

        count = family_counts.get(family, 0)

        status = "Available" if count else "Missing"

        print(
            f"{family:<20} "
            f"{count:>5} files    {status}"
        )

    print("\nUnknown files:",
          family_counts.get("Unknown", 0))

    unknown = valid[
        valid["AttackFamily"] == "Unknown"
    ]

    if not unknown.empty:

        print("\nUnmapped folders:")

        for folder in sorted(unknown["Folder"].unique()):
            print(" -", folder)

    print("\n" + "=" * 75)
    print("FEATURE SCHEMA SUMMARY")
    print("=" * 75)

    print("Unique schemas:", len(schema_counts))

    for index, (schema, count) in enumerate(
        schema_counts.items(), start=1
    ):

        print(f"\nSchema {index}")
        print(f"Files: {count}")
        print(f"Columns: {len(schema)}")
        print(list(schema))

    output_path = (
        OUTPUT_DIR / "dataset_inventory.csv"
    )

    inventory.to_csv(output_path, index=False)

    print("\n" + "=" * 75)
    print("INSPECTION COMPLETED")
    print("=" * 75)

    print("Inventory saved to:", output_path)

    print(
        "Files with read errors:",
        len(inventory) - len(valid)
    )

    print(
        "Total dataset size:",
        round(inventory["SizeMB"].sum() / 1024, 2),
        "GB"
    )


if __name__ == "__main__":
    main()