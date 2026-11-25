from pathlib import Path
import math

import pandas as pd
import requests


BASE_URL = "http://127.0.0.1:8000/api/multiclass"

PROJECT_ROOT = Path(__file__).resolve().parent

DATA_PATH = (
    PROJECT_ROOT
    / "data/processed/multiclass/verified/validation.csv"
)


def main():

    print("=" * 75)
    print("CONTEXT-AWARE RISK API TEST")
    print("=" * 75)

    # Model information

    response = requests.get(
        f"{BASE_URL}/model-info",
        timeout=30,
    )

    response.raise_for_status()

    feature_names = response.json()["features"]

    print("\nModel information: PASSED")

    # Device inventory

    response = requests.get(
        f"{BASE_URL}/device-profiles",
        timeout=30,
    )

    response.raise_for_status()

    inventory = response.json()

    assert inventory["total_devices"] == 5

    print("Device inventory API: PASSED")

    # Load validation sample

    df = pd.read_csv(
        DATA_PATH,
        usecols=feature_names + [
            "Label",
            "AttackFamily",
        ],
        dtype={
            name: "float32"
            for name in feature_names
        },
    )

    sample = df[df["Label"] == 6].iloc[0]

    features = {
        name: float(sample[name])
        for name in feature_names
    }

    devices = [
        item["device_id"]
        for item in inventory["devices"]
    ]

    devices.append("unknown-device")

    results = {}

    print("\nSAME TRAFFIC, DIFFERENT DEVICES")

    # Risk assessment tests

    for device_id in devices:

        response = requests.post(
            f"{BASE_URL}/assess-risk",
            json={
                "features": features,
                "device_id": device_id,
                "source": "risk_api_test",
            },
            timeout=60,
        )

        response.raise_for_status()

        result = response.json()

        risk = result["risk_assessment"]

        assert 0 <= risk["risk_score"] <= 100

        assert risk["risk_reconstruction"]["passed"]

        assert result["incident_created"] is False

        assert result["response_executed"] is False

        assert risk["containment_authorized"] is False

        results[device_id] = risk

        print(
            f"{device_id:20s} | "
            f"Risk: {risk['risk_score']:7.2f} | "
            f"{risk['risk_level'].upper():8s} | "
            f"HTTP {response.status_code}"
        )

    # Context differentiation

    assert (
        results["medical-001"]["risk_score"]
        >
        results["sensor-001"]["risk_score"]
    )

    assert (
        results["gateway-001"]["risk_score"]
        >
        results["sensor-001"]["risk_score"]
    )

    print("\nContext differentiation: PASSED")

    # Prediction consistency

    reference_probability = results[
        "sensor-001"
    ]["attack_probability"]

    for risk in results.values():

        assert math.isclose(
            risk["attack_probability"],
            reference_probability,
            abs_tol=1e-8,
            rel_tol=0,
        )

    print("Prediction consistency: PASSED")

    # Unknown device handling

    unknown = results["unknown-device"]

    assert unknown[
        "device_context"
    ]["context_known"] is False

    assert unknown[
        "device_context"
    ]["identity_verified"] is False

    assert unknown[
        "containment_authorized"
    ] is False

    print("Unknown device handling: PASSED")

    # Invalid input tests

    invalid_payloads = [

        {
            "features": {},
        },

        {
            "features": features,
            "device_id": True,
        },

        {
            "features": features,
            "device_id": "",
        },

        {
            "features": features,
            "device_id": "   ",
        },
    ]

    print("\nINVALID INPUT TESTS")

    for index, payload in enumerate(
        invalid_payloads,
        start=1,
    ):

        response = requests.post(
            f"{BASE_URL}/assess-risk",
            json=payload,
            timeout=30,
        )

        assert response.status_code == 422, (
            f"Invalid input {index} failed: "
            f"HTTP {response.status_code}"
        )

        print(
            f"Invalid input {index}: "
            "PASSED (HTTP 422)"
        )

    print("\n" + "=" * 75)
    print("ALL CONTEXT RISK API TESTS PASSED")
    print("=" * 75)

    print("No incident responses were executed.")


if __name__ == "__main__":
    main()