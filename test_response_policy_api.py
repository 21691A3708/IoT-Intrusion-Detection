
from pathlib import Path

import pandas as pd
import requests


ROOT = Path(__file__).resolve().parent

BASE_URL = (
    "http://127.0.0.1:8000/api/multiclass"
)

DATA_PATH = (
    ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)


def main():

    print("=" * 75)
    print("CONTROLLED RESPONSE POLICY API TEST")
    print("=" * 75)

    response = requests.get(
        f"{BASE_URL}/response-policy",
        timeout=30,
    )

    response.raise_for_status()

    policy = response.json()

    assert policy["simulation_only"]

    assert not policy[
        "real_network_execution_enabled"
    ]

    print("Policy information: PASSED")

    response = requests.get(
        f"{BASE_URL}/model-info",
        timeout=30,
    )

    response.raise_for_status()

    features_list = response.json()["features"]

    df = pd.read_csv(
        DATA_PATH,
        usecols=features_list + ["Label"],
        dtype={
            feature: "float32"
            for feature in features_list
        },
    )

    mirai = df[df["Label"] == 6].iloc[0]

    features = {
        feature: float(mirai[feature])
        for feature in features_list
    }

    devices = [
        "sensor-001",
        "camera-001",
        "gateway-001",
        "medical-001",
        "industrial-001",
        "unknown-device",
    ]

    print("\nRESPONSE PLANNING TESTS")

    for device_id in devices:

        response = requests.post(
            f"{BASE_URL}/plan-response",
            json={
                "features": features,
                "device_id": device_id,
                "source": "response_policy_api_test",
            },
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        plan = data["response_plan"]

        assert not data["incident_created"]

        assert not data["response_executed"]

        assert not plan["containment_eligible"]

        assert not plan["containment_authorized"]

        assert not plan["approval_granted"]

        assert not plan["real_network_action_executed"]

        print(
            f"{device_id:20s} | "
            f"Risk: {plan['risk_score']:6.2f} | "
            f"{plan['risk_level']:8s} | "
            f"{plan['response_status']} | "
            f"HTTP {response.status_code}"
        )

        print(
            "  Primary action:",
            plan["primary_action"],
        )

        print(
            "  Incident required:",
            plan["incident_required"],
        )

        print(
            "  Restrictions:",
            ", ".join(plan["restriction_reasons"]),
        )

    print("\nDevice protection: PASSED")

    # --------------------------------------------------
    # INVALID INPUT TESTS
    # --------------------------------------------------

    missing = features.copy()

    missing.pop(features_list[0])

    invalid_requests = [

        {
            "features": missing,
        },

        {
            "features": features,
            "device_id": "",
        },

        {
            "features": features,
            "device_id": True,
        },

        # A caller must not be able to override
        # device identity verification.

        {
            "features": features,
            "device_id": "camera-001",
            "identity_verified": True,
        },

        # A caller must not be able to grant approval
        # through the planning endpoint.

        {
            "features": features,
            "approval_granted": True,
        },
    ]

    print("\nINVALID INPUT TESTS")

    for index, payload in enumerate(
        invalid_requests,
        start=1,
    ):

        response = requests.post(
            f"{BASE_URL}/plan-response",
            json=payload,
            timeout=30,
        )

        assert response.status_code == 422, (
            response.text
        )

        print(
            f"Invalid input {index}: "
            "PASSED (HTTP 422)"
        )

    print("\n" + "=" * 75)
    print("ALL RESPONSE POLICY API TESTS PASSED")
    print("=" * 75)

    print("No incidents were persisted.")
    print("No network actions were executed.")


if __name__ == "__main__":
    main()
