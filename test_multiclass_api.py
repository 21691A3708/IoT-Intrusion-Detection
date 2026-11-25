from pathlib import Path
import json
import math

import pandas as pd
import requests


BASE_URL = "http://127.0.0.1:8000/api/multiclass"

PROJECT_ROOT = Path(__file__).resolve().parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)


def main():

    print("=" * 70)
    print("MULTICLASS FASTAPI INTEGRATION TEST")
    print("=" * 70)

    # ----------------------------------------------
    # MODEL INFORMATION
    # ----------------------------------------------

    response = requests.get(
        f"{BASE_URL}/model-info",
        timeout=30,
    )

    response.raise_for_status()

    model_info = response.json()

    features = model_info["features"]

    assert model_info["feature_count"] == 36
    assert model_info["class_count"] == 8

    print("\nModel information: PASSED")

    print(
        "Model version:",
        model_info["model_version"],
    )

    # ----------------------------------------------
    # LOAD VALIDATION SAMPLES
    # ----------------------------------------------

    df = pd.read_csv(
        DATA_PATH,
        usecols=features + [
            "Label",
            "AttackFamily",
        ],
    )

    samples = (
        df.groupby("Label")
        .head(1)
        .sort_values("Label")
    )

    records = []
    single_results = []

    print("\nSINGLE PREDICTION TESTS")

    for _, row in samples.iterrows():

        record = {
            name: float(row[name])
            for name in features
        }

        records.append(record)

        response = requests.post(
            f"{BASE_URL}/predict",
            json={
                "features": record,
                "source": "api_test",
            },
            timeout=30,
        )

        response.raise_for_status()

        result = response.json()

        single_results.append(result)

        assert len(
            result["class_probabilities"]
        ) == 8

        assert 0 <= result[
            "attack_probability"
        ] <= 1

        assert result[
            "incident_created"
        ] is False

        assert result[
            "response_executed"
        ] is False

        print(
            f"Actual: {row['AttackFamily']:16s} | "
            f"Predicted: "
            f"{result['predicted_family']:16s} | "
            f"Attack probability: "
            f"{result['attack_probability']:.4f} | "
            f"HTTP {response.status_code}"
        )

    # ----------------------------------------------
    # BATCH PREDICTION
    # ----------------------------------------------

    response = requests.post(
        f"{BASE_URL}/predict-batch",
        json={
            "records": records,
            "source": "batch_test",
        },
        timeout=60,
    )

    response.raise_for_status()

    batch = response.json()

    assert batch["total_records"] == len(records)

    for single, batched in zip(
        single_results,
        batch["predictions"],
    ):

        assert single["predicted_label"] == (
            batched["predicted_label"]
        )

        assert math.isclose(
            single["attack_probability"],
            batched["attack_probability"],
            abs_tol=1e-6,
        )

    print("\nBatch prediction: PASSED")

    # ----------------------------------------------
    # INVALID INPUT TESTS
    # ----------------------------------------------

    invalid_records = {}

    missing = records[0].copy()
    missing.pop(features[0])

    invalid_records["Missing feature"] = missing

    extra = records[0].copy()
    extra["unknown_feature"] = 100

    invalid_records["Unexpected feature"] = extra

    boolean = records[0].copy()
    boolean[features[0]] = True

    invalid_records["Boolean feature"] = boolean

    non_numeric = records[0].copy()
    non_numeric[features[0]] = "invalid"

    invalid_records["Non-numeric feature"] = (
        non_numeric
    )

    numeric_string = records[0].copy()
    numeric_string[features[0]] = "100"

    invalid_records["Numeric string"] = (
        numeric_string
    )

    print("\nINVALID INPUT TESTS")

    for name, record in invalid_records.items():

        response = requests.post(
            f"{BASE_URL}/predict",
            json={"features": record},
            timeout=30,
        )

        assert response.status_code == 422, (
            f"{name}: expected HTTP 422, "
            f"received {response.status_code}"
        )

        print(f"{name}: PASSED (HTTP 422)")

    # Empty batch test

    response = requests.post(
        f"{BASE_URL}/predict-batch",
        json={"records": []},
        timeout=30,
    )

    assert response.status_code == 422

    print("Empty batch: PASSED (HTTP 422)")

    print("\nSAMPLE API RESPONSE")

    print(
        json.dumps(
            single_results[0],
            indent=4,
        )
    )

    print("\n" + "=" * 70)
    print("ALL MULTICLASS API TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()