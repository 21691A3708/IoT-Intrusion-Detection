from pathlib import Path
import time

import pandas as pd
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)

BASE_URL = "http://127.0.0.1:8000/api/multiclass"

API_URL = f"{BASE_URL}/predict"

INTERVAL_SECONDS = 1

SAMPLES_PER_CLASS = 5

RANDOM_STATE = 42


def run_simulator():

    print("=" * 75)
    print("MULTICLASS IoT TRAFFIC REPLAY SIMULATOR")
    print("=" * 75)

    response = requests.get(
        f"{BASE_URL}/model-info",
        timeout=30,
    )

    response.raise_for_status()

    model_info = response.json()

    feature_columns = model_info["features"]

    print(
        "\nModel:",
        model_info["model_version"],
    )

    df = pd.read_csv(
        DATASET_PATH,
        usecols=feature_columns + [
            "Label",
            "AttackFamily",
        ],
    )

    # Select balanced demonstration samples.

    samples = []

    for label, group in df.groupby("Label"):

        selected = group.sample(
            n=min(SAMPLES_PER_CLASS, len(group)),
            random_state=RANDOM_STATE,
        )

        samples.append(selected)

    replay_data = (
        pd.concat(samples, ignore_index=True)
        .sample(
            frac=1,
            random_state=RANDOM_STATE,
        )
        .reset_index(drop=True)
    )

    print(
        f"Replay records: {len(replay_data)}"
    )

    print("\nReplay class distribution:")

    print(
        replay_data["AttackFamily"]
        .value_counts()
        .to_string()
    )

    print("\nStarting traffic replay...")
    print("Press Ctrl+C to stop.\n")

    successful = 0
    failed = 0
    correct_family = 0
    high_confidence_alerts = 0

    try:

        for index, row in replay_data.iterrows():

            features = {
                name: float(row[name])
                for name in feature_columns
            }

            try:

                response = requests.post(
                    API_URL,
                    json={
                        "features": features,
                        "source": (
                            "multiclass_simulator"
                        ),
                    },
                    timeout=30,
                )

                response.raise_for_status()

                result = response.json()

                successful += 1

                if result["predicted_label"] == int(
                    row["Label"]
                ):

                    correct_family += 1

                if result["high_confidence_alert"]:

                    high_confidence_alerts += 1

                print(
                    f"[{index + 1:02d}] "
                    f"Actual: "
                    f"{row['AttackFamily']:16s} | "
                    f"Predicted: "
                    f"{result['predicted_family']:16s}"
                )

                print(
                    f"     Attack probability: "
                    f"{result['attack_probability']:.4f}"
                )

                print(
                    f"     Family confidence: "
                    f"{result['prediction_confidence']:.4f}"
                )

                print(
                    f"     Detection status: "
                    f"{result['detection_status']}"
                )

                print()

            except requests.RequestException as error:

                failed += 1

                print(
                    f"Request failed: {error}"
                )

            time.sleep(INTERVAL_SECONDS)

    except KeyboardInterrupt:

        print("\nSimulation stopped by user.")

    print("=" * 75)
    print("MULTICLASS REPLAY SUMMARY")
    print("=" * 75)

    print(f"Successful requests: {successful}")
    print(f"Failed requests: {failed}")
    print(f"Correct family predictions: {correct_family}")

    print(
        f"High-confidence alerts: "
        f"{high_confidence_alerts}"
    )

    if successful:

        print(
            f"Replay family accuracy: "
            f"{correct_family / successful:.2%}"
        )

    print("\nMode: Prediction only")
    print("No incident responses were executed.")

    print(
        "Replay results are demonstration metrics, "
        "not independent model evaluation."
    )


if __name__ == "__main__":
    run_simulator()