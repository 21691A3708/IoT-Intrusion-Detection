
from pathlib import Path
from copy import deepcopy
import json

import pandas as pd

from test_response_policy import (
    make_fixture,
)

from backend.app.multiclass_ml_service import (
    FEATURE_NAMES,
)

from backend.app.response_lifecycle_service import (
    ResponseLifecycleService,
    ResponseStateError,
)


ROOT = Path(__file__).resolve().parent

OUTPUT_DIR = (
    ROOT
    / "results"
    / "multiclass"
    / "response_lifecycle"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_PATH = (
    ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)


def expect_failure(
    name,
    function,
    exception_type=ResponseStateError,
):

    try:

        function()

    except exception_type:

        print(f"{name}: PASSED")

        return

    raise AssertionError(
        f"{name}: Expected exception not raised."
    )


def create_fixture(
    service,
    **kwargs,
):

    prediction, risk = make_fixture(
        **kwargs
    )

    return service._create_from_assessment(

        prediction=prediction,

        risk=risk,

        synthetic_fixture=True,
    )


def main():

    print("=" * 75)

    print("CONTROLLED RESPONSE LIFECYCLE TEST")

    print("=" * 75)

    service = ResponseLifecycleService()

    actor = "synthetic-test-analyst"

    # --------------------------------------------------
    # TEST 1: CREATE ELIGIBLE RESPONSE
    # --------------------------------------------------

    record = create_fixture(service)

    response_id = record["response_id"]

    assert record["status"] == "pending_approval"

    assert not record["approval_granted"]

    assert not record["simulation_executed"]

    assert not record["containment_authorized"]

    print("\nCreate pending response: PASSED")

    # --------------------------------------------------
    # TEST 2: EXECUTION WITHOUT APPROVAL
    # --------------------------------------------------

    expect_failure(

        "Execution without approval blocked",

        lambda: service.execute(
            response_id,
            actor,
        ),
    )

    # --------------------------------------------------
    # TEST 3: PREMATURE ROLLBACK
    # --------------------------------------------------

    expect_failure(

        "Premature rollback blocked",

        lambda: service.rollback(
            response_id,
            actor,
            "Invalid rollback test",
        ),
    )

    # --------------------------------------------------
    # TEST 4: APPROVE RESPONSE
    # --------------------------------------------------

    record = service.decide(

        response_id=response_id,

        decision="approve",

        actor=actor,

        reason="Synthetic laboratory test approval",
    )

    assert record["status"] == "approved"

    assert record["approval_granted"]

    assert record["simulation_authorized"]

    assert not record["containment_authorized"]

    print("Approve eligible response: PASSED")

    # --------------------------------------------------
    # TEST 5: DUPLICATE APPROVAL
    # --------------------------------------------------

    expect_failure(

        "Duplicate approval blocked",

        lambda: service.decide(

            response_id,

            "approve",

            actor,

            "Duplicate approval",
        ),
    )

    # --------------------------------------------------
    # TEST 6: EXECUTE SIMULATION
    # --------------------------------------------------

    record = service.execute(

        response_id=response_id,

        actor=actor,
    )

    assert record["status"] == "simulated"

    assert record["simulation_executed"]

    assert not record["response_executed"]

    assert not record["real_network_action_executed"]

    assert record["execution"][
        "new_device_state"
    ] == "simulated_isolated"

    print("Approved simulation execution: PASSED")

    # --------------------------------------------------
    # TEST 7: DUPLICATE EXECUTION
    # --------------------------------------------------

    expect_failure(

        "Duplicate execution blocked",

        lambda: service.execute(
            response_id,
            actor,
        ),
    )

    # --------------------------------------------------
    # TEST 8: ROLLBACK
    # --------------------------------------------------

    record = service.rollback(

        response_id=response_id,

        actor=actor,

        reason="Synthetic test completed",
    )

    assert record["status"] == "rolled_back"

    assert record["rollback"][
        "simulation_rollback_executed"
    ]

    assert record["rollback"][
        "restored_device_state"
    ] == "simulated_unmodified"

    print("Simulated rollback: PASSED")

    # --------------------------------------------------
    # TEST 9: DUPLICATE ROLLBACK
    # --------------------------------------------------

    expect_failure(

        "Duplicate rollback blocked",

        lambda: service.rollback(

            response_id,

            actor,

            "Duplicate rollback",
        ),
    )

    # --------------------------------------------------
    # TEST 10: AUDIT VERIFICATION
    # --------------------------------------------------

    actions = [

        event["action"]

        for event in record["audit_logs"]
    ]

    assert actions == [

        "response_created",

        "response_approved",

        "simulation_executed",

        "simulation_rolled_back",
    ]

    assert all(

        event["simulation_only"]

        for event in record["audit_logs"]
    )

    print("Audit lifecycle verification: PASSED")

    completed_record = deepcopy(record)

    # --------------------------------------------------
    # TEST 11: REJECTION WORKFLOW
    # --------------------------------------------------

    rejected = create_fixture(service)

    rejected_id = rejected["response_id"]

    rejected = service.decide(

        rejected_id,

        "reject",

        actor,

        "Insufficient investigation evidence",
    )

    assert rejected["status"] == "rejected"

    assert not rejected["approval_granted"]

    print("Reject response: PASSED")

    expect_failure(

        "Rejected response execution blocked",

        lambda: service.execute(
            rejected_id,
            actor,
        ),
    )

    expect_failure(

        "Rejected response approval blocked",

        lambda: service.decide(

            rejected_id,

            "approve",

            actor,

            "Invalid approval",
        ),
    )

    # --------------------------------------------------
    # TEST 12: PROTECTED AND UNKNOWN DEVICES
    # --------------------------------------------------

    restricted_records = []

    for field in [

        "context_known",

        "identity_verified",

        "containment_allowed",
    ]:

        prediction, risk = make_fixture()

        risk["device_context"][field] = False

        restricted = service._create_from_assessment(

            prediction,

            risk,

            synthetic_fixture=True,
        )

        assert restricted["status"] == "restricted"

        restricted_id = restricted["response_id"]

        expect_failure(

            f"Approval blocked: {field}",

            lambda: service.decide(

                restricted_id,

                "approve",

                actor,

                "Invalid approval",
            ),
        )

        expect_failure(

            f"Execution blocked: {field}",

            lambda: service.execute(

                restricted_id,

                actor,
            ),
        )

        restricted_records.append(restricted)

    # --------------------------------------------------
    # TEST 13: NON-SYNTHETIC APPROVAL PATH
    # --------------------------------------------------

    prediction, risk = make_fixture()

    expect_failure(

        "Non-synthetic eligible fixture blocked",

        lambda: service._create_from_assessment(

            prediction,

            risk,

            synthetic_fixture=False,
        ),
    )

    # --------------------------------------------------
    # TEST 14: RECORD MUTATION PROTECTION
    # --------------------------------------------------

    copied = service.get_response(
        response_id
    )

    copied["status"] = "approved"

    original = service.get_response(
        response_id
    )

    assert original["status"] == "rolled_back"

    print("External record mutation blocked: PASSED")

    # --------------------------------------------------
    # TEST 15: INVALID RESPONSE IDENTIFIER
    # --------------------------------------------------

    expect_failure(

        "Unknown response identifier",

        lambda: service.get_response(
            "invalid-response-id"
        ),

        KeyError,
    )

    # --------------------------------------------------
    # TEST 16: INTEGRATED TRAFFIC SCENARIOS
    # --------------------------------------------------

    print("\nINTEGRATED TRAFFIC SCENARIOS")

    df = pd.read_csv(

        DATA_PATH,

        usecols=FEATURE_NAMES + ["Label"],

        dtype={

            feature: "float32"

            for feature in FEATURE_NAMES
        },
    )

    mirai = df[df["Label"] == 6].iloc[0]

    features = {

        feature: float(mirai[feature])

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

    integrated_records = []

    for device_id in devices:

        result = service.create_from_traffic(

            features=features,

            device_id=device_id,
        )

        assert result["status"] == "restricted"

        assert not result["synthetic_fixture"]

        assert not result["simulation_executed"]

        assert not result["containment_authorized"]

        assert not result["incident_created"]

        print(

            f"{device_id:20s} | "

            f"{result['status']:12s} | "

            f"Risk: "

            f"{result['response_plan']['risk_score']:.2f}"
        )

        expect_failure(

            f"Approval blocked: {device_id}",

            lambda: service.decide(

                result["response_id"],

                "approve",

                actor,

                "Invalid approval",
            ),
        )

        integrated_records.append(result)

    # --------------------------------------------------
    # SAVE TEST RESULTS
    # --------------------------------------------------

    all_records = [

        completed_record,

        rejected,

        *restricted_records,

        *integrated_records,
    ]

    with open(

        OUTPUT_DIR / "response_lifecycle_examples.json",

        "w",

        encoding="utf-8",

    ) as file:

        json.dump(

            all_records,

            file,

            indent=4,
        )

    audit_rows = [

        {

            **event,

            "details": json.dumps(
                event["details"]
            ),
        }

        for item in all_records

        for event in item["audit_logs"]
    ]

    pd.DataFrame(audit_rows).to_csv(

        OUTPUT_DIR / "response_audit_logs.csv",

        index=False,
    )

    print("\n" + "=" * 75)

    print("ALL RESPONSE LIFECYCLE TESTS PASSED")

    print("=" * 75)

    print("Results saved to:", OUTPUT_DIR)

    print("No actual network actions were executed.")

    print("No database incidents were created.")


if __name__ == "__main__":

    main()
