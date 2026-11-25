from pathlib import Path
from uuid import uuid4
import json

import pandas as pd
import requests


ROOT = Path(__file__).resolve().parent

BASE_URL = "http://127.0.0.1:8000"
RESPONSE_URL = f"{BASE_URL}/api/responses"

TIMEOUT = 60

DATA_PATH = (
    ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)

OUTPUT_DIR = (
    ROOT
    / "results"
    / "multiclass"
    / "response_lifecycle_api"
)


def check_status(response, expected, name):

    assert response.status_code == expected, (
        f"{name} failed. "
        f"Expected HTTP {expected}, "
        f"received HTTP {response.status_code}. "
        f"Body: {response.text}"
    )

    print(
        f"{name}: PASSED "
        f"(HTTP {response.status_code})"
    )


def main():

    print("=" * 75)
    print("CONTROLLED RESPONSE LIFECYCLE API TEST")
    print("=" * 75)

    # Service information

    response = requests.get(
        f"{RESPONSE_URL}/info",
        timeout=TIMEOUT,
    )

    check_status(
        response, 200, "Lifecycle information"
    )

    info = response.json()

    assert info["simulation_only"]
    assert not info["real_network_execution_enabled"]
    assert not info["synthetic_fixture_creation_via_api"]
    assert not info["persistent_storage"]

    # Load model features

    response = requests.get(
        f"{BASE_URL}/api/multiclass/model-info",
        timeout=TIMEOUT,
    )

    response.raise_for_status()

    feature_names = response.json()["features"]

    df = pd.read_csv(
        DATA_PATH,
        usecols=feature_names + ["Label"],
        dtype={
            feature: "float32"
            for feature in feature_names
        },
    )

    sample = df[df["Label"] == 6].iloc[0]

    features = {
        feature: float(sample[feature])
        for feature in feature_names
    }

    devices = [
        "sensor-001",
        "camera-001",
        "gateway-001",
        "medical-001",
        "industrial-001",
        "unknown-device",
    ]

    actor = "api-test-analyst"

    records = []

    print("\nDEVICE RESPONSE TESTS")

    for device_id in devices:

        print("\n" + "-" * 65)
        print("Device:", device_id)

        response = requests.post(
            RESPONSE_URL,
            json={
                "features": features,
                "device_id": device_id,
            },
            timeout=TIMEOUT,
        )

        check_status(
            response, 201, "Create response"
        )

        record = response.json()
        response_id = record["response_id"]

        assert record["status"] == "restricted"
        assert not record["synthetic_fixture"]
        assert not record["approval_granted"]
        assert not record["simulation_executed"]
        assert not record["containment_authorized"]
        assert not record["incident_created"]
        assert not record["real_network_action_executed"]

        print("Response ID:", response_id)

        print(
            "Risk score:",
            record["response_plan"]["risk_score"],
        )

        url = f"{RESPONSE_URL}/{response_id}"

        # Retrieve response

        response = requests.get(
            url,
            timeout=TIMEOUT,
        )

        check_status(
            response, 200, "Retrieve response"
        )

        assert response.json() == record

        # Restricted approval

        response = requests.post(
            f"{url}/decision",
            json={
                "decision": "approve",
                "actor": actor,
                "reason": "Restricted response test",
            },
            timeout=TIMEOUT,
        )

        check_status(
            response, 409,
            "Restricted approval blocked"
        )

        # Unauthorized execution

        response = requests.post(
            f"{url}/execute",
            json={"actor": actor},
            timeout=TIMEOUT,
        )

        check_status(
            response, 409,
            "Unauthorized execution blocked"
        )

        # Invalid rollback

        response = requests.post(
            f"{url}/rollback",
            json={
                "actor": actor,
                "reason": "Invalid rollback test",
            },
            timeout=TIMEOUT,
        )

        check_status(
            response, 409,
            "Invalid rollback blocked"
        )

        # Audit history

        response = requests.get(
            f"{url}/audit",
            timeout=TIMEOUT,
        )

        check_status(
            response, 200,
            "Retrieve audit history"
        )

        audit = response.json()

        assert audit["total_events"] == 1
        assert audit["status"] == "restricted"

        assert audit["audit_logs"][0]["action"] == (
            "response_created"
        )

        # Verify state remains unchanged

        response = requests.get(
            url,
            timeout=TIMEOUT,
        )

        response.raise_for_status()

        final_record = response.json()

        assert final_record == record

        records.append(final_record)

        print("Restricted state preserved: PASSED")

    # Identifier validation

    print("\nIDENTIFIER VALIDATION TESTS")

    response = requests.get(
        f"{RESPONSE_URL}/{uuid4()}",
        timeout=TIMEOUT,
    )

    check_status(
        response, 404,
        "Unknown response identifier"
    )

    response = requests.get(
        f"{RESPONSE_URL}/invalid-uuid",
        timeout=TIMEOUT,
    )

    check_status(
        response, 422, "Invalid UUID"
    )

    # Invalid request validation

    print("\nINVALID REQUEST TESTS")

    invalid_payloads = [
        {
            "features": {},
            "device_id": "sensor-001",
        },
        {
            "features": features,
            "device_id": "",
        },
        {
            "features": features,
            "device_id": True,
        },
        {
            "features": features,
            "device_id": "camera-001",
            "identity_verified": True,
        },
        {
            "features": features,
            "device_id": "camera-001",
            "approval_granted": True,
        },
        {
            "features": features,
            "device_id": "camera-001",
            "synthetic_fixture": True,
        },
        {
            "features": features,
            "device_id": "camera-001",
            "risk_score": 100,
        },
        {
            "features": features,
            "device_id": "camera-001",
            "containment_authorized": True,
        },
    ]

    for index, payload in enumerate(
        invalid_payloads, start=1
    ):

        response = requests.post(
            RESPONSE_URL,
            json=payload,
            timeout=TIMEOUT,
        )

        check_status(
            response, 422,
            f"Invalid payload {index}"
        )

    response_id = records[0]["response_id"]

    response = requests.post(
        f"{RESPONSE_URL}/{response_id}/decision",
        json={
            "decision": "force_approve",
            "actor": actor,
            "reason": "Invalid decision test",
        },
        timeout=TIMEOUT,
    )

    check_status(
        response, 422, "Invalid decision"
    )

    # Save results

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_DIR / "api_response_records.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(records, file, indent=4)

    summary = []

    for record in records:

        plan = record["response_plan"]

        summary.append({
            "ResponseID": record["response_id"],
            "DeviceID": plan["device_id"],
            "PredictedFamily": plan["predicted_family"],
            "RiskScore": plan["risk_score"],
            "RiskLevel": plan["risk_level"],
            "Status": record["status"],
            "ApprovalGranted": record["approval_granted"],
            "SimulationExecuted": record["simulation_executed"],
            "RealNetworkActionExecuted":
                record["real_network_action_executed"],
            "AuditEvents": len(record["audit_logs"]),
        })

    pd.DataFrame(summary).to_csv(
        OUTPUT_DIR / "api_lifecycle_summary.csv",
        index=False,
    )

    print("\n" + "=" * 75)
    print("ALL RESPONSE LIFECYCLE API TESTS PASSED")
    print("=" * 75)

    print("Device scenarios:", len(records))
    print("Unauthorized executions: 0")
    print("Actual network actions: 0")
    print("Database incidents created: 0")
    print("Results saved to:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
