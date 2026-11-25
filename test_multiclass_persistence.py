from pathlib import Path
import json

import pandas as pd

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from backend.app.database import engine

from backend.app.multiclass_ml_service import (
    FEATURE_NAMES,
)

from backend.app.multiclass_repository import (
    get_persisted_response,
    insert_audit_event,
)

from backend.app.multiclass_persistence_service import (
    build_response_record,
    persist_initial_record,
)


ROOT = Path(__file__).resolve().parent

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
    / "database_persistence"
)


def expect_constraint_failure(
    connection,
    name,
    operation,
):

    try:

        # SAVEPOINT isolates the failed statement
        # from the surrounding transaction.

        with connection.begin_nested():

            operation()

    except IntegrityError:

        print(f"{name}: PASSED")

    else:

        raise AssertionError(
            f"{name}: constraint did not reject operation."
        )


def verify_rolled_back(ids):

    tables = {
        "predictions": ids["prediction_id"],
        "risk_assessments": ids["risk_assessment_id"],
        "incidents": ids["incident_id"],
        "response_records": ids["response_id"],
        "response_audit_logs": ids["audit_id"],
    }

    with engine.connect() as connection:

        for table, record_id in tables.items():

            if record_id is None:

                continue

            # Table names are fixed internal constants.

            query = text(
                f"SELECT COUNT(*) "
                f"FROM multiclass.{table} "
                f"WHERE id = :id"
            )

            count = connection.execute(
                query,
                {"id": record_id},
            ).scalar_one()

            assert count == 0, (
                f"Unexpected retained row in {table}"
            )

            print(
                f"Rollback verification "
                f"({table}): PASSED"
            )


def main():

    print("=" * 80)
    print("MULTICLASS DATABASE PERSISTENCE TEST")
    print("=" * 80)

    df = pd.read_csv(
        DATA_PATH,
        usecols=FEATURE_NAMES + ["Label"],
        dtype={
            feature: "float32"
            for feature in FEATURE_NAMES
        },
    )

    sample = df[df["Label"] == 6].iloc[0]

    features = {
        feature: float(sample[feature])
        for feature in FEATURE_NAMES
    }

    devices = [
        "sensor-001",
        "camera-001",
        "gateway-001",
        "medical-001",
        "industrial-001",
        "unknown-device",
    ]

    summaries = []

    for device_id in devices:

        print("\n" + "-" * 75)
        print("DEVICE:", device_id)

        record = build_response_record(
            features=features,
            device_id=device_id,
        )

        with engine.connect() as connection:

            transaction = connection.begin()

            try:

                result = persist_initial_record(
                    connection=connection,
                    record=record,
                    features=features,
                    device_id=device_id,
                    source="persistence_test",
                )

                print("Prediction insertion: PASSED")
                print("Risk insertion: PASSED")

                assert result["incident_created"]

                print("Incident insertion: PASSED")

                assert result["status"] == "restricted"

                print("Response insertion: PASSED")

                assert len(result["audit_logs"]) == 1

                assert result["audit_logs"][0][
                    "action"
                ] == "response_created"

                print("Audit insertion: PASSED")

                assert result["storage_mode"] == (
                    "postgresql"
                )

                assert not result["synthetic_fixture"]
                assert not result["approval_granted"]
                assert not result["simulation_executed"]
                assert not result["containment_authorized"]
                assert not result[
                    "real_network_action_executed"
                ]

                print("Safety flags: PASSED")

                response_id = result["response_id"]

                retrieved = get_persisted_response(
                    connection,
                    response_id,
                )

                assert retrieved == result

                print("Database retrieval: PASSED")

                assert (
                    result["prediction"]["predicted_label"]
                    ==
                    record["prediction"]["predicted_label"]
                )

                assert (
                    result["risk_assessment"]["risk_score"]
                    ==
                    record["risk_assessment"]["risk_score"]
                )

                print("Prediction and risk consistency: PASSED")

                ids = {
                    "prediction_id":
                        result["prediction_id"],

                    "risk_assessment_id":
                        result["risk_assessment_id"],

                    "incident_id":
                        result["incident_id"],

                    "response_id":
                        result["response_id"],

                    "audit_id":
                        result["audit_logs"][0]["audit_id"],
                }

                # Database safety tests

                expect_constraint_failure(
                    connection,
                    "Invalid label blocked",
                    lambda: connection.execute(
                        text("""
                            UPDATE multiclass.predictions
                            SET predicted_label = 8
                            WHERE id = :id
                        """),
                        {"id": ids["prediction_id"]},
                    ),
                )

                expect_constraint_failure(
                    connection,
                    "Invalid probability blocked",
                    lambda: connection.execute(
                        text("""
                            UPDATE multiclass.predictions
                            SET calibrated_attack_probability = 1.5
                            WHERE id = :id
                        """),
                        {"id": ids["prediction_id"]},
                    ),
                )

                expect_constraint_failure(
                    connection,
                    "Invalid risk score blocked",
                    lambda: connection.execute(
                        text("""
                            UPDATE multiclass.risk_assessments
                            SET risk_score = 101
                            WHERE id = :id
                        """),
                        {"id": ids["risk_assessment_id"]},
                    ),
                )

                expect_constraint_failure(
                    connection,
                    "Real network execution blocked",
                    lambda: connection.execute(
                        text("""
                            UPDATE multiclass.response_records
                            SET real_network_action_executed = TRUE
                            WHERE id = :id
                        """),
                        {"id": response_id},
                    ),
                )

                expect_constraint_failure(
                    connection,
                    "Actual containment blocked",
                    lambda: connection.execute(
                        text("""
                            UPDATE multiclass.response_records
                            SET containment_authorized = TRUE
                            WHERE id = :id
                        """),
                        {"id": response_id},
                    ),
                )

                expect_constraint_failure(
                    connection,
                    "Unauthorized approval blocked",
                    lambda: connection.execute(
                        text("""
                            UPDATE multiclass.response_records
                            SET status = 'approved',
                                approval_granted = TRUE
                            WHERE id = :id
                        """),
                        {"id": response_id},
                    ),
                )

                # Verify duplicate audit sequence.

                from uuid import uuid4

                duplicate = dict(
                    record["audit_logs"][0]
                )

                duplicate["audit_id"] = str(uuid4())

                expect_constraint_failure(
                    connection,
                    "Duplicate audit sequence blocked",
                    lambda: insert_audit_event(
                        connection,
                        duplicate,
                        1,
                    ),
                )

                # Confirm that failed operations
                # did not change the original record.

                final = get_persisted_response(
                    connection,
                    response_id,
                )

                assert final == result

                print("Original state preserved: PASSED")

                summaries.append({
                    "DeviceID": device_id,

                    "PredictedFamily":
                        result["prediction"]["predicted_family"],

                    "RiskScore":
                        result["risk_assessment"]["risk_score"],

                    "RiskLevel":
                        result["risk_assessment"]["risk_level"],

                    "ResponseStatus":
                        result["status"],

                    "IncidentCreatedInTransaction":
                        result["incident_created"],

                    "AuditEvents":
                        len(result["audit_logs"]),

                    "DatabaseWriteTest": "PASSED",

                    "PermanentStorage": False,
                })

            finally:

                transaction.rollback()

                print("Test transaction rolled back.")

        verify_rolled_back(ids)

    # --------------------------------------------------
    # Test automatic rollback after a database failure.
    # --------------------------------------------------

    print("\nAUTOMATIC TRANSACTION ROLLBACK TEST")

    record = build_response_record(
        features=features,
        device_id="camera-001",
    )

    failure_ids = None

    try:

        with engine.begin() as connection:

            result = persist_initial_record(
                connection=connection,
                record=record,
                features=features,
                device_id="camera-001",
                source="rollback_test",
            )

            failure_ids = {
                "prediction_id":
                    result["prediction_id"],

                "risk_assessment_id":
                    result["risk_assessment_id"],

                "incident_id":
                    result["incident_id"],

                "response_id":
                    result["response_id"],

                "audit_id":
                    result["audit_logs"][0]["audit_id"],
            }

            # Deliberately violate the audit constraint.
            # This exception must roll back everything.

            duplicate = dict(
                record["audit_logs"][0]
            )

            duplicate["audit_id"] = str(uuid4())

            insert_audit_event(
                connection,
                duplicate,
                1,
            )

    except IntegrityError:

        print("Database failure detected: PASSED")

    else:

        raise AssertionError(
            "Expected transaction failure did not occur."
        )

    assert failure_ids is not None

    verify_rolled_back(failure_ids)

    print("Automatic transaction rollback: PASSED")

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    pd.DataFrame(summaries).to_csv(
        OUTPUT_DIR / "persistence_test_summary.csv",
        index=False,
    )

    with open(
        OUTPUT_DIR / "persistence_test_summary.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            summaries,
            file,
            indent=4,
        )

    print("\n" + "=" * 80)
    print("ALL DATABASE PERSISTENCE TESTS PASSED")
    print("=" * 80)

    print("Device scenarios:", len(summaries))

    print("Automatic transaction rollback: PASSED")

    print("Permanent test records retained: 0")

    print("Actual network actions: 0")

    print("Results saved to:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
