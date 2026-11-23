
import time
import random
import requests
import pandas as pd
from pathlib import Path

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "clean_iot_dataset.csv"

API_URL = "http://127.0.0.1:8000/api/predictions"

# Time interval between simulated traffic records
INTERVAL_SECONDS = 1

# Number of records to send.
# Set to None to run continuously.
TOTAL_RECORDS = 50

# --------------------------------------------------
# MODEL FEATURES
# These must match the trained model's exact order.
# --------------------------------------------------

FEATURE_COLUMNS = [
    'Header_Length',
    'Protocol Type',
    'Time_To_Live',
    'Rate',
    'fin_flag_number',
    'syn_flag_number',
    'rst_flag_number',
    'psh_flag_number',
    'ack_flag_number',
    'ece_flag_number',
    'cwr_flag_number',
    'ack_count',
    'syn_count',
    'fin_count',
    'rst_count',
    'HTTP',
    'HTTPS',
    'DNS',
    'SSH',
    'IRC',
    'TCP',
    'UDP',
    'DHCP',
    'ARP',
    'ICMP',
    'IGMP',
    'IPv',
    'LLC',
    'Tot sum',
    'Min',
    'Max',
    'AVG',
    'Std',
    'Tot size',
    'IAT',
    'Variance'
]


def load_dataset():
    """Load and validate the cleaned CICIoT2023 dataset."""

    print("\nLoading CICIoT2023 dataset...")

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    required_columns = FEATURE_COLUMNS + ['Label']

    missing_columns = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required dataset columns: {missing_columns}"
        )

    # Keep only model features and the target label.
    df = df[FEATURE_COLUMNS + ['Label']].copy()

    # Remove invalid feature records.
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].apply(
        pd.to_numeric, errors='coerce'
    )

    df.replace([float('inf'), float('-inf')], float('nan'), inplace=True)
    df.dropna(subset=FEATURE_COLUMNS + ['Label'], inplace=True)

    df['Label'] = pd.to_numeric(df['Label'], errors='coerce')
    df.dropna(subset=['Label'], inplace=True)
    df = df[df['Label'].isin([0, 1])]

    if df.empty:
        raise ValueError("No valid records found in the dataset.")

    benign = df[df['Label'] == 0]
    attacks = df[df['Label'] == 1]

    if benign.empty or attacks.empty:
        raise ValueError(
            "Dataset must contain both benign and attack records."
        )

    print(f"Dataset loaded: {len(df):,} records")
    print(f"Benign records: {len(benign):,}")
    print(f"Attack records: {len(attacks):,}")
    print(f"Model features: {len(FEATURE_COLUMNS)}")

    return benign, attacks


def send_traffic(record, sequence_number):
    """Send one traffic record to the FastAPI prediction endpoint."""

    features = {
        column: float(record[column])
        for column in FEATURE_COLUMNS
    }

    payload = {
        "features": features,
        "source": "simulator"
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=15
        )

        response.raise_for_status()
        result = response.json()

        prediction = result.get("prediction", "unknown")
        probability = result.get("attack_probability", 0)
        risk = result.get("risk_level", "unknown")
        incident = result.get("incident_created", False)

        print(
            f"\n[{sequence_number}] "
            f"Prediction: {prediction.upper()} | "
            f"Attack Probability: {probability:.4f} | "
            f"Risk: {risk.upper()} | "
            f"Incident Created: {incident}"
        )

    except requests.exceptions.RequestException as error:
        print(f"\n[{sequence_number}] API request failed: {error}")
        return False

    return True


def run_simulator():
    print("=" * 60)
    print("       IoT LIVE TRAFFIC REPLAY SIMULATOR")
    print("=" * 60)

    benign_records, attack_records = load_dataset()

    print("\nStarting traffic simulation...")
    print("Press CTRL+C to stop.\n")

    sequence_number = 0
    successful_requests = 0
    failed_requests = 0

    try:
        while (
            TOTAL_RECORDS is None
            or sequence_number < TOTAL_RECORDS
        ):
            sequence_number += 1

            # Alternate between benign and attack traffic.
            if sequence_number % 2 == 0:
                record = attack_records.sample(
                    n=1,
                    random_state=random.randint(0, 1_000_000)
                ).iloc[0]
                traffic_type = "ATTACK"
            else:
                record = benign_records.sample(
                    n=1,
                    random_state=random.randint(0, 1_000_000)
                ).iloc[0]
                traffic_type = "BENIGN"

            print(
                f"\nSending record {sequence_number} "
                f"(selected source class: {traffic_type})..."
            )

            success = send_traffic(record, sequence_number)

            if success:
                successful_requests += 1
            else:
                failed_requests += 1

            time.sleep(INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n\nSimulation stopped by user.")

    print("\n" + "=" * 60)
    print("SIMULATION SUMMARY")
    print("=" * 60)
    print(f"Records attempted: {sequence_number}")
    print(f"Successful requests: {successful_requests}")
    print(f"Failed requests: {failed_requests}")
    print("=" * 60)


if __name__ == "__main__":
    run_simulator()
