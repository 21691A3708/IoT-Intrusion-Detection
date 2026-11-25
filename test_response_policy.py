
from pathlib import Path
from copy import deepcopy
import json

import pandas as pd

from backend.app.multiclass_ml_service import (
    FEATURE_NAMES,
    predict_traffic,
)

from backend.app.context_risk_service import (
    assess_prediction_risk,
)

from backend.app.response_policy_service import (
    evaluate_response_policy,
    plan_traffic_response,
    get_response_policy_info,
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
    / "response_policy"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


DEVICES = [
    "sensor-001",
    "camera-001",
    "gateway-001",
    "medical-001",
    "industrial-001",
    "unknown-device",
]


def make_fixture(
    probability=0.99,
    confidence=0.95,
    risk_score=85.0,
    family="Mirai",
    label=6,
):

    prediction = {
        "calibrated_attack_probability": probability,
        "prediction_confidence": confidence,
        "predicted_family": family,
        "predicted_label": label,
        "model_version": "synthetic_test_fixture",
    }

    if risk_score < 25:
        level = "low"
    elif risk_score < 50:
        level = "medium"
    elif risk_score < 75:
        level = "high"
    else:
        level = "critical"

    risk = {
        "risk_score": risk_score,
        "risk_level": level,
        "attack_probability": probability,
        "risk_policy_version": "synthetic_test_fixture",

        "recommended_action": "record_and_monitor",

        "attack_impact": {
            "impact_available": True,
        },

        "device_context": {
            "device_id": "synthetic-lab-device",
            "device_name": "Synthetic Test Device",
            "context_known": True,
            "identity_verified": True,
            "containment_allowed": True,
            "simulation_only": True,
        },
    }

    return prediction, risk


def main():

    print("=" * 75)
    print("CONTROLLED RESPONSE POLICY TEST")
    print("=" * 75)

    print("\nPOLICY CONFIGURATION")

    print(json.dumps(
        get_response_policy_info(),
        indent=4,
    ))

    # --------------------------------------------------
    # SYNTHETIC POLICY TESTS
    # --------------------------------------------------

    print("\nSYNTHETIC POLICY TESTS")

    prediction, risk = make_fixture()

    result = evaluate_response_policy(
        prediction,
        risk,
    )

    assert result["containment_eligible"]
    assert result["approval_required"]
    assert result["response_status"] == "pending_approval"
    assert not result["approval_granted"]
    assert not result["containment_authorized"]
    assert not result["response_executed"]

    print("Eligible containment: PASSED")

    # Device protection tests

    for field in [
        "context_known",
        "identity_verified",
        "containment_allowed",
    ]:

        modified = deepcopy(risk)

        modified["device_context"][field] = False

        result = evaluate_response_policy(
            prediction,
            modified,
        )

        assert not result["containment_eligible"]
        assert not result["containment_authorized"]
        assert result["response_status"] == "restricted"

        print(f"Restricted {field}: PASSED")

    # Insufficient probability

    p, r = make_fixture(probability=0.89)

    result = evaluate_response_policy(p, r)

    assert not result["containment_eligible"]

    print("Insufficient attack probability: PASSED")

    # Insufficient family confidence

    p, r = make_fixture(confidence=0.69)

    result = evaluate_response_policy(p, r)

    assert not result["containment_eligible"]

    print("Insufficient family confidence: PASSED")

    # Insufficient risk

    p, r = make_fixture(risk_score=74.99)

    result = evaluate_response_policy(p, r)

    assert not result["containment_eligible"]

    print("Insufficient risk score: PASSED")

    # Exact policy boundaries

    p, r = make_fixture(
        probability=0.90,
        confidence=0.70,
        risk_score=75.0,
    )

    result = evaluate_response_policy(p, r)

    assert result["containment_eligible"]

    print("Exact policy boundaries: PASSED")

    # Unsupported attack family

    p, r = make_fixture(
        family="BruteForce",
        label=4,
    )

    result = evaluate_response_policy(p, r)

    assert not result["containment_eligible"]

    assert not result["safety_checks"][
        "family_has_validation_coverage"
    ]

    print("Unsupported BruteForce coverage: PASSED")

    # Benign prediction

    p, r = make_fixture(
        probability=0.10,
        confidence=0.95,
        risk_score=5.0,
        family="Benign",
        label=0,
    )

    result = evaluate_response_policy(p, r)

    assert not result["incident_required"]
    assert not result["containment_eligible"]

    print("Low-risk benign traffic: PASSED")

    # High probability but medium risk

    p, r = make_fixture(risk_score=40.0)

    result = evaluate_response_policy(p, r)

    assert result["incident_required"]
    assert not result["containment_eligible"]

    print("High probability with medium risk: PASSED")

    # Missing device identifier

    p, r = make_fixture()

    r["device_context"]["device_id"] = None

    result = evaluate_response_policy(p, r)

    assert not result["containment_eligible"]

    print("Missing device identifier: PASSED")

    # --------------------------------------------------
    # VALIDATION DATA SCENARIOS
    # --------------------------------------------------

    print("\nVALIDATION DATA SCENARIOS")

    df = pd.read_csv(
        DATA_PATH,
        usecols=FEATURE_NAMES + [
            "Label",
            "AttackFamily",
        ],
        dtype={
            feature: "float32"
            for feature in FEATURE_NAMES
        },
    )

    samples = (
        df.groupby("Label")
        .head(1)
        .sort_values("Label")
    )

    records = []

    for _, row in samples.iterrows():

        features = {
            feature: float(row[feature])
            for feature in FEATURE_NAMES
        }

        prediction = predict_traffic(features)

        print("\n" + "=" * 75)

        print(
            "Actual family:",
            row["AttackFamily"],
        )

        print(
            "Predicted family:",
            prediction["predicted_family"],
        )

        for device_id in DEVICES:

            risk = assess_prediction_risk(
                prediction=prediction,
                device_id=device_id,
            )

            result = evaluate_response_policy(
                prediction=prediction,
                risk_assessment=risk,
            )

            # Existing demonstration devices must
            # never become eligible for containment.

            assert not result["containment_eligible"]

            assert not result["containment_authorized"]

            assert not result["response_executed"]

            assert not result[
                "real_network_action_executed"
            ]

            print(
                f"{device_id:20s} | "
                f"Risk: {result['risk_score']:6.2f} | "
                f"{result['risk_level']:8s} | "
                f"{result['response_status']}"
            )

            records.append({

                "ActualFamily":
                    row["AttackFamily"],

                "PredictedFamily":
                    result["predicted_family"],

                "DeviceID":
                    device_id,

                "AttackProbability":
                    result["attack_probability"],

                "FamilyConfidence":
                    result["family_confidence"],

                "RiskScore":
                    result["risk_score"],

                "RiskLevel":
                    result["risk_level"],

                "IncidentRequired":
                    result["incident_required"],

                "PrimaryAction":
                    result["primary_action"],

                "ProposedAction":
                    result["proposed_containment_action"],

                "ContainmentEligible":
                    result["containment_eligible"],

                "ResponseStatus":
                    result["response_status"],

                "RestrictionReasons":
                    "; ".join(
                        result["restriction_reasons"]
                    ),
            })

    # --------------------------------------------------
    # INTEGRATED PIPELINE TEST
    # --------------------------------------------------

    sample = samples.iloc[0]

    features = {
        feature: float(sample[feature])
        for feature in FEATURE_NAMES
    }

    integrated = plan_traffic_response(
        features=features,
        device_id="camera-001",
    )

    assert "prediction" in integrated
    assert "risk_assessment" in integrated
    assert "response_plan" in integrated

    assert not integrated["incident_created"]
    assert not integrated["response_executed"]

    print("\nIntegrated response pipeline: PASSED")

    # --------------------------------------------------
    # SAVE RESULTS
    # --------------------------------------------------

    results = pd.DataFrame(records)

    results.to_csv(
        OUTPUT_DIR / "response_policy_scenarios.csv",
        index=False,
    )

    print("\n" + "=" * 75)
    print("RESPONSE POLICY SUMMARY")
    print("=" * 75)

    print("Total scenarios:", len(results))

    print(
        "Incidents recommended:",
        int(results["IncidentRequired"].sum()),
    )

    print(
        "Containment eligible:",
        int(results["ContainmentEligible"].sum()),
    )

    print("\nResponse status distribution:")

    print(
        results["ResponseStatus"]
        .value_counts()
        .to_string()
    )

    print("\nPrimary action distribution:")

    print(
        results["PrimaryAction"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 75)
    print("ALL RESPONSE POLICY TESTS PASSED")
    print("=" * 75)

    print("Results saved to:", OUTPUT_DIR)

    print("No incidents were persisted.")

    print("No network responses were executed.")


if __name__ == "__main__":
    main()
