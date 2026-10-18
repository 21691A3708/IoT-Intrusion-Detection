
from pathlib import Path

DATA_DIR = Path("data/raw/extracted/CSV")

if not DATA_DIR.exists():
    raise FileNotFoundError(f"Dataset folder not found: {DATA_DIR}")

csv_files = sorted(DATA_DIR.rglob("*.csv"))

print(f"Total CSV files found: {len(csv_files)}\n")

# Show files for the two classes used in the current experiment.
target_groups = ["Benign_Final", "DoS-UDP_Flood"]

for group in target_groups:
    folder = DATA_DIR / group

    print(f"\n{'=' * 65}")
    print(f"FOLDER: {group}")
    print("=" * 65)

    if not folder.exists():
        print("Folder not found.")
        continue

    files = sorted(folder.glob("*.csv"))

    for file in files:
        size_mb = file.stat().st_size / (1024 * 1024)
        print(f"{file.name:<40} {size_mb:>8.2f} MB")

print("\nCapture file listing completed.")
