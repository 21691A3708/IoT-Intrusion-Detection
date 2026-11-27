
from pathlib import Path
import json
import pandas as pd

# Input directories
source = Path("results/multiclass/frontend_detection_samples")

validation_path = Path(
    "data/processed/multiclass/verified/validation.csv"
)

# Output directory
destination = Path("results/multiclass/batch_test_datasets")
destination.mkdir(parents=True, exist_ok=True)

# Supported sample families
families = [
    "benign",
    "ddos",
    "dos",
    "reconnaissance",
    "spoofing",
    "mirai",
    "webbased"
]

# Generate seven-record CSV
records = []

for family in families:

    file_path = source / f"{family}.json"

    with open(file_path, "r", encoding="utf-8-sig") as file:
        features = json.load(file)

    records.append({
        **features,
        "ExpectedFamily": family
    })

df = pd.DataFrame(records)

df.to_csv(
    destination / "seven_attack_samples.csv",
    index=False
)

print("PASS: Seven-sample CSV generated")

# Load existing validation dataset
validation = pd.read_csv(validation_path)

# Generate 100-record and 2500-record CSV files
for size in [100, 2500]:

    sample = validation.sample(
        n=size,
        random_state=42
    )

    output_path = destination / f"batch_test_{size}.csv"

    sample.to_csv(output_path, index=False)

    print(f"PASS: {size}-record CSV generated")

print("=" * 60)
print("PASS: All batch test datasets generated")
print("Output directory:")
print(destination.resolve())
print("=" * 60)
