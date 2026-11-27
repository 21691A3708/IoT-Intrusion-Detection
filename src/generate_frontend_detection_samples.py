import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]

DATASET = (
    ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)

OUTPUT = (
    ROOT
    / "results"
    / "multiclass"
    / "frontend_detection_samples"
)

FEATURES = [
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

FAMILIES = [
    "Benign",
    "DDoS",
    "DoS",
    "Reconnaissance",
    "BruteForce",
    "Spoofing",
    "Mirai",
    "WebBased",
]


def main():

    if not DATASET.exists():
        raise FileNotFoundError(DATASET)

    OUTPUT.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(
        DATASET,
        usecols=FEATURES + ["AttackFamily"],
    )

    manifest = []

    for family in FAMILIES:

        rows = df[df["AttackFamily"] == family]

        if rows.empty:
            print(f"SKIPPED: {family} - no validation samples")
            continue

        row = rows.sample(
            n=1,
            random_state=42,
        ).iloc[0]

        features = {
            feature: float(row[feature])
            for feature in FEATURES
        }

        filename = f"{family.lower()}.json"

        path = OUTPUT / filename

        path.write_text(
            json.dumps(
                features,
                indent=2,
                allow_nan=False,
            ),
            encoding="utf-8",
        )

        manifest.append({
            "file": filename,
            "expected_family": family,
            "source": "verified_validation_dataset",
        })

        print(f"CREATED: {filename}")

    (OUTPUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(f"\nTotal samples: {len(manifest)}")
    print(f"Output directory: {OUTPUT}")


if __name__ == "__main__":
    main()
