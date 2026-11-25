from pathlib import Path
from uuid import uuid4
import argparse
import json

import pandas as pd
import requests


ROOT = Path(__file__).resolve().parent

BASE_URL = "http://127.0.0.1:8000"

API_URL = f"{BASE_URL}/api/persistent-responses"

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
    / "persistent_response_api"
)

MANIFEST_PATH = (
    OUTPUT_DIR / "persisted_test_records.json"
)

DEVICES = [
    "sensor-001",
    "camera-001",
    "gateway-001",
    "medical-001",
    "industrial-001",
    "unknown-device",
]


def check_status(response, expected, name):

    assert response.status_code == expected, (
        f"{name}: Expected HTTP {expected}, "
        f"received HTTP {response.status_code}. "
        f"Body: {response.text}"
    )

    print(
        f"{name}: PASSED "
        f"(HTTP {response.status_code})"
    )

    return response.json()


def save_manifest(manifest):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = MANIFEST_PATH.with_suffix(
        ".tmp"
    )

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(manifest, file, indent=4)

    temporary_path.replace(MANIFEST_PATH)


def load_samples():

    response = requests.get(
        f"{BASE_URL}/api/multiclass/model-info",
        timeout=TIMEOUT,
    )

    info = check_status(
        response,
        200,
        "Model information",
    )

    features = info["features"]

    df = pd.read_csv(
        DATA_PATH,
        usecols=features + ["Label"],
        dtype={
            feature: "float32"
            for feature in features
        },
    )

    samples = {}

    for label in (0, 6):

        rows = df[df["Label"] == label]

        assert not rows.empty

        samples[label] = [
            {
                feature: float(row[feature])
                for feature in features
            }
            for _, row in rows.head(100).iterrows()
        ]

    return samples


def verify_record(record):

    response_id = record["response_id"]

    response = requests.get(
        f"{API_URL}/{response_id}",
        timeout=TIMEOUT,
    )

    retrieved = check_status(
        response,
        200,
        "Retrieve persisted response",
    )

    assert retrieved == record

    response = requests.get(
        f"{API_URL}/{response_id}/audit",
        timeout=TIMEOUT,
    )

    audit = check_status(
        response,
        200,
        "Retrieve audit history",
    )

    assert audit["persistent_storage"]
    assert audit["simulation_only"]
    assert audit["total_events"] == 1

    assert audit["audit_logs"] == (
        record["audit_logs"]
    )

    assert audit["audit_logs"][0]["action"] == (
        "response_created"
    )

    assert not retrieved["approval_granted"]
    assert not retrieved["simulation_authorized"]
    assert not retrieved["simulation_executed"]
    assert not retrieved["containment_authorized"]
    assert not retrieved["real_network_action_executed"]

    print("Record consistency: PASSED")
    print("Safety restrictions: PASSED")


def create_record(
    features,
    device_id,
    manifest,
    expected_incident,
):

    response = requests.post(
        API_URL,
        json={
            "features": features,
            "device_id": device_id,
            "source": manifest["source"],
        },
        timeout=TIMEOUT,
    )

    record = check_status(
        response,
        201,
        "Create persistent response",
    )

    # Save the record immediately so its ID
    # is available even if a later test fails.

    manifest["records"].append(record)

    save_manifest(manifest)

    assert record["storage_mode"] == "postgresql"

    assert record["source"] == manifest["source"]

    assert not record["synthetic_fixture"]

    assert record["incident_created"] == (
        expected_incident
    )

    if expected_incident:

        assert record["incident_id"] is not None
        assert record["incident_status"] == "open"
        assert record["status"] == "restricted"

    else:

        assert record["incident_id"] is None

    verify_record(record)

    print(
        "Predicted family:",
        record["prediction"]["predicted_family"],
    )

    print(
        "Risk score:",
        round(
            record["risk_assessment"]["risk_score"],
            2,
        ),
    )

    print(
        "Risk level:",
        record["risk_assessment"]["risk_level"],
    )

    print("Response status:", record["status"])

    print("Incident created:", record["incident_created"])

    return record


def test_listing(manifest):

    source = manifest["source"]

    records = manifest["records"]

    expected_ids = {
        record["response_id"]
        for record in records
    }

    response = requests.get(
        API_URL,
        params={
            "source": source,
            "limit": 100,
        },
        timeout=TIMEOUT,
    )

    result = check_status(
        response,
        200,
        "List persisted responses",
    )

    assert result["total"] == len(records)

    actual_ids = {
        record["response_id"]
        for record in result["records"]
    }

    assert actual_ids == expected_ids

    print("Listing consistency: PASSED")

    # Pagination testing

    page_ids = []

    for offset in range(len(records)):

        response = requests.get(
            API_URL,
            params={
                "source": source,
                "limit": 1,
                "offset": offset,
            },
            timeout=TIMEOUT,
        )

        response.raise_for_status()

        page = response.json()

        assert page["returned"] == 1

        page_ids.append(
            page["records"][0]["response_id"]
        )

    assert len(page_ids) == len(set(page_ids))
    assert set(page_ids) == expected_ids

    print("Pagination: PASSED")

    # Filter testing

    filter_tests = [
        (
            "risk_level",
            ["low", "medium", "high", "critical"],
            lambda record: record[
                "risk_assessment"
            ]["risk_level"],
        ),
        (
            "predicted_family",
            [
                "Benign",
                "DDoS",
                "DoS",
                "Reconnaissance",
                "BruteForce",
                "Spoofing",
                "Mirai",
                "WebBased",
            ],
            lambda record: record[
                "prediction"
            ]["predicted_family"],
        ),
        (
            "status",
            ["restricted", "not_required"],
            lambda record: record["status"],
        ),
    ]

    for field, values, getter in filter_tests:

        for value in values:

            response = requests.get(
                API_URL,
                params={
                    "source": source,
                    field: value,
                    "limit": 100,
                },
                timeout=TIMEOUT,
            )

            response.raise_for_status()

            filtered = response.json()

            expected = {
                record["response_id"]
                for record in records
                if getter(record) == value
            }

            actual = {
                record["response_id"]
                for record in filtered["records"]
            }

            assert expected == actual
            assert filtered["total"] == len(expected)

        print(f"{field} filtering: PASSED")


def test_invalid_requests(features, manifest):

    source = manifest["source"]

    invalid_payloads = [
        {"features": {}},

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
            "identity_verified": True,
        },

        {
            "features": features,
            "approval_granted": True,
        },

        {
            "features": features,
            "synthetic_fixture": True,
        },

        {
            "features": features,
            "containment_authorized": True,
        },

        {
            "features": features,
            "risk_score": 100,
        },
    ]

    for index, payload in enumerate(
        invalid_payloads,
        start=1,
    ):

        payload["source"] = source

        response = requests.post(
            API_URL,
            json=payload,
            timeout=TIMEOUT,
        )

        check_status(
            response,
            422,
            f"Invalid payload {index}",
        )

    invalid_queries = [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"risk_level": "invalid"},
        {"predicted_family": "invalid"},
        {"status": "invalid"},
    ]

    for index, params in enumerate(
        invalid_queries,
        start=1,
    ):

        response = requests.get(
            API_URL,
            params=params,
            timeout=TIMEOUT,
        )

        check_status(
            response,
            422,
            f"Invalid query {index}",
        )

    response = requests.get(
        f"{API_URL}/{uuid4()}",
        timeout=TIMEOUT,
    )

    check_status(
        response,
        404,
        "Unknown response ID",
    )

    response = requests.get(
        f"{API_URL}/invalid-uuid",
        timeout=TIMEOUT,
    )

    check_status(
        response,
        422,
        "Malformed response ID",
    )

    # Confirm invalid requests did not add records
    # under the unique test source.

    test_listing(manifest)


def create_tests():

    print("=" * 75)
    print("PERSISTENT RESPONSE API CREATION TEST")
    print("=" * 75)

    if MANIFEST_PATH.exists():

        raise RuntimeError(
            "Test manifest already exists. "
            "Use verify mode or inspect the existing "
            "test records before creating more."
        )

    response = requests.get(
        f"{API_URL}/info",
        timeout=TIMEOUT,
    )

    info = check_status(
        response,
        200,
        "Persistent service information",
    )

    assert info["persistent_storage"]
    assert info["transactional_writes"]
    assert info["simulation_only"]
    assert not info["real_network_execution_enabled"]

    samples = load_samples()

    # Find a suitable no-incident sample using
    # the prediction-only response planning API.

    benign_features = None

    for features in samples[0]:

        response = requests.post(
            f"{BASE_URL}/api/multiclass/plan-response",
            json={
                "features": features,
                "device_id": "sensor-001",
            },
            timeout=TIMEOUT,
        )

        response.raise_for_status()

        plan = response.json()["response_plan"]

        if not plan["incident_required"]:

            benign_features = features

            break

    assert benign_features is not None, (
        "No suitable no-incident sample found "
        "among the first 100 benign rows."
    )

    manifest = {
        "source": (
            f"persistent_api_test_{uuid4().hex}"
        ),
        "completed": False,
        "records": [],
    }

    # Save the source before the first database write.

    save_manifest(manifest)

    print("Test source:", manifest["source"])

    print("\nNO-INCIDENT SCENARIO")

    create_record(
        features=benign_features,
        device_id="sensor-001",
        manifest=manifest,
        expected_incident=False,
    )

    print("No-incident persistence: PASSED")

    attack_features = samples[6][0]

    for device_id in DEVICES:

        print("\n" + "-" * 70)
        print("DEVICE:", device_id)

        create_record(
            features=attack_features,
            device_id=device_id,
            manifest=manifest,
            expected_incident=True,
        )

    print("\nLISTING AND FILTERING TESTS")

    test_listing(manifest)

    print("\nINVALID REQUEST TESTS")

    test_invalid_requests(
        attack_features,
        manifest,
    )

    manifest["completed"] = True

    save_manifest(manifest)

    print("\n" + "=" * 75)
    print("ALL PERSISTENT API CREATION TESTS PASSED")
    print("=" * 75)

    print(
        "Permanent test responses:",
        len(manifest["records"]),
    )

    print(
        "Incidents created:",
        sum(
            record["incident_created"]
            for record in manifest["records"]
        ),
    )

    print("Actual network actions: 0")

    print("Test source:", manifest["source"])

    print("Manifest:", MANIFEST_PATH)


def verify_tests():

    print("=" * 75)
    print("PERSISTENT RESPONSE RESTART VERIFICATION")
    print("=" * 75)

    with open(
        MANIFEST_PATH,
        encoding="utf-8",
    ) as file:

        manifest = json.load(file)

    assert manifest["completed"], (
        "The previous creation test did not finish."
    )

    records = manifest["records"]

    assert len(records) == 7

    for record in records:

        print(
            "\nResponse ID:",
            record["response_id"],
        )

        verify_record(record)

    test_listing(manifest)

    summary = []

    for record in records:

        summary.append({
            "ResponseID":
                record["response_id"],

            "DeviceID":
                record["requested_device_identifier"],

            "PredictedFamily":
                record["prediction"]["predicted_family"],

            "RiskScore":
                record["risk_assessment"]["risk_score"],

            "RiskLevel":
                record["risk_assessment"]["risk_level"],

            "ResponseStatus":
                record["status"],

            "IncidentCreated":
                record["incident_created"],

            "AuditEvents":
                len(record["audit_logs"]),

            "StorageMode":
                record["storage_mode"],

            "RestartVerification":
                "PASSED",

            "RealNetworkAction":
                record["real_network_action_executed"],
        })

    pd.DataFrame(summary).to_csv(
        OUTPUT_DIR / "restart_verification_summary.csv",
        index=False,
    )

    print("\n" + "=" * 75)
    print("PERSISTENT RECORD VERIFICATION PASSED")
    print("=" * 75)

    print("Persisted responses:", len(records))

    print(
        "Persisted incidents:",
        sum(
            record["incident_created"]
            for record in records
        ),
    )

    print("Audit histories preserved:", len(records))

    print("Actual network actions: 0")

    print("Results saved to:", OUTPUT_DIR)


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "mode",
        choices=["create", "verify"],
    )

    args = parser.parse_args()

    if args.mode == "create":

        create_tests()

    else:

        verify_tests()


if __name__ == "__main__":
    main()
