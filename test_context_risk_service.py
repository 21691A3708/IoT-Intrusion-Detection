from pathlib import Path
import math
import json

import pandas as pd

from backend.app.multiclass_ml_service import (

    FEATURE_NAMES,

    predict_traffic,
)

from backend.app.context_risk_service import (

    calculate_risk_score,

    get_risk_level,

    assess_prediction_risk,

    assess_traffic_risk,
)

from backend.app.device_context_service import (

    get_device_context,

    list_device_profiles,
)

from backend.app.attack_impact_service import (

    calculate_attack_impact,
)


PROJECT_ROOT = Path(__file__).resolve().parent

DATA_PATH = (

    PROJECT_ROOT

    / "data/processed/multiclass/verified/validation.csv"
)

OUTPUT_DIR = (

    PROJECT_ROOT

    / "results/multiclass/context_risk"
)


def main():

    OUTPUT_DIR.mkdir(

        parents=True,

        exist_ok=True,
    )

    print("=" * 75)
    print("CONTEXT-AWARE RISK SERVICE TEST")
    print("=" * 75)

    # ----------------------------------------------
    # MATHEMATICAL TESTS
    # ----------------------------------------------

    assert calculate_risk_score(

        0, 1, 1, 1

    ) == 0

    assert math.isclose(

        calculate_risk_score(1, 1, 1, 1),

        100,

        abs_tol=1e-8,
    )

    assert math.isclose(

        calculate_risk_score(

            0.95, 0.90, 0.80, 0.70

        ),

        77.90,

        abs_tol=1e-8,
    )

    print("\nRisk formula: PASSED")

    # ----------------------------------------------
    # SEVERITY BOUNDARY TESTS
    # ----------------------------------------------

    boundaries = [

        (0, "low"),

        (24.99, "low"),

        (25, "medium"),

        (49.99, "medium"),

        (50, "high"),

        (74.99, "high"),

        (75, "critical"),

        (100, "critical"),
    ]

    for score, expected in boundaries:

        assert get_risk_level(score) == expected

    print("Severity boundaries: PASSED")

    # ----------------------------------------------
    # ATTACK IMPACT TESTS
    # ----------------------------------------------

    probabilities = {

        "Benign": 0.10,

        "DDoS": 0.50,

        "DoS": 0.30,

        "Reconnaissance": 0.0,

        "BruteForce": 0.0,

        "Spoofing": 0.0,

        "Mirai": 0.10,

        "WebBased": 0.0,
    }

    impact = calculate_attack_impact(
        probabilities
    )

    assert math.isclose(

        impact["expected_impact"],

        0.77 / 0.90,

        abs_tol=1e-8,
    )

    print("Expected attack impact: PASSED")

    # ----------------------------------------------
    # UNKNOWN DEVICE TEST
    # ----------------------------------------------

    unknown = get_device_context(

        "unregistered-device"
    )

    assert unknown["context_known"] is False

    assert unknown["containment_allowed"] is False

    assert unknown["identity_verified"] is False

    print("Unknown device fallback: PASSED")

    # ----------------------------------------------
    # LOAD VALIDATION DATA
    # ----------------------------------------------

    df = pd.read_csv(

        DATA_PATH,

        usecols=FEATURE_NAMES + [

            "Label",

            "AttackFamily",
        ],
    )

    samples = (

        df.groupby("Label")

        .head(1)

        .sort_values("Label")
    )

    devices = [

        profile["device_id"]

        for profile in list_device_profiles()
    ]

    devices.append(None)

    summaries = []

    full_results = []

    first_features = None

    # ----------------------------------------------
    # TEST SAME TRAFFIC ACROSS DIFFERENT DEVICES
    # ----------------------------------------------

    for _, row in samples.iterrows():

        features = {

            name: float(row[name])

            for name in FEATURE_NAMES
        }

        if first_features is None:

            first_features = features.copy()

        prediction = predict_traffic(
            features
        )

        print("\n" + "=" * 75)

        print(

            "Actual family:",

            row["AttackFamily"],
        )

        print(

            "Predicted family:",

            prediction["predicted_family"],
        )

        print(

            "Attack probability:",

            f"{prediction['attack_probability']:.6f}",
        )

        for device_id in devices:

            result = assess_prediction_risk(

                prediction,

                device_id=device_id,
            )

            assert 0 <= result["risk_score"] <= 100

            assert result[
                "risk_reconstruction"
            ]["passed"]

            assert result[
                "containment_authorized"
            ] is False

            assert result[
                "response_executed"
            ] is False

            context = result[
                "device_context"
            ]

            print(

                f"{context['device_name']:25s} | "

                f"Risk: {result['risk_score']:7.2f} | "

                f"{result['risk_level'].upper():8s} | "

                f"{result['recommended_action']}"
            )

            summaries.append({

                "ActualFamily":
                    row["AttackFamily"],

                "PredictedFamily":
                    prediction["predicted_family"],

                "DeviceID":
                    context["device_id"],

                "DeviceName":
                    context["device_name"],

                "AttackProbability":
                    result["attack_probability"],

                "Criticality":
                    context["criticality"],

                "Exposure":
                    context["exposure"],

                "ExpectedImpact":
                    result["attack_impact"][
                        "expected_impact"
                    ],

                "RiskScore":
                    result["risk_score"],

                "RiskLevel":
                    result["risk_level"],

                "RecommendedAction":
                    result["recommended_action"],

                "ContextKnown":
                    context["context_known"],
            })

            full_results.append({

                "actual_family":
                    row["AttackFamily"],

                "prediction":
                    prediction,

                "risk_assessment":
                    result,
            })

    # ----------------------------------------------
    # MONOTONICITY TESTS
    # ----------------------------------------------

    assert calculate_risk_score(

        0.90, 0.90, 0.80, 0.50

    ) > calculate_risk_score(

        0.90, 0.20, 0.80, 0.50
    )

    assert calculate_risk_score(

        0.90, 0.70, 0.80, 0.50

    ) > calculate_risk_score(

        0.50, 0.70, 0.80, 0.50
    )

    print("\nRisk monotonicity: PASSED")

    # ----------------------------------------------
    # COMPLETE PIPELINE TEST
    # ----------------------------------------------

    integrated = assess_traffic_risk(

        first_features,

        device_id="camera-001",
    )

    assert integrated["mode"] == (

        "risk_assessment_only"
    )

    assert integrated[
        "incident_created"
    ] is False

    assert integrated[
        "response_executed"
    ] is False

    print("Integrated prediction and risk: PASSED")

    # ----------------------------------------------
    # INVALID INPUT TESTS
    # ----------------------------------------------

    invalid_values = [

        -0.1,

        1.1,

        float("nan"),

        float("inf"),

        True,

        "0.5",
    ]

    for value in invalid_values:

        try:

            calculate_risk_score(

                value, 0.5, 0.5, 0.5
            )

        except ValueError:

            print(

                f"Invalid value {value!r}: PASSED"
            )

        else:

            raise AssertionError(

                f"Invalid value accepted: {value!r}"
            )

    # ----------------------------------------------
    # SAVE RESULTS
    # ----------------------------------------------

    summary_df = pd.DataFrame(
        summaries
    )

    summary_df.to_csv(

        OUTPUT_DIR / "risk_assessment_summary.csv",

        index=False,
    )

    with open(

        OUTPUT_DIR / "risk_assessment_examples.json",

        "w",

        encoding="utf-8",

    ) as file:

        json.dump(

            full_results,

            file,

            indent=4,
        )

    print("\n" + "=" * 75)
    print("RISK ASSESSMENT SUMMARY")
    print("=" * 75)

    print(

        "Total scenarios:",

        len(summary_df),
    )

    print("\nRisk level distribution:")

    print(

        summary_df["RiskLevel"]

        .value_counts()

        .to_string()
    )

    print("\nMean risk by device:")

    print(

        summary_df.groupby("DeviceName")[
            "RiskScore"
        ]

        .mean()

        .sort_values(ascending=False)

        .to_string()
    )

    print("\n" + "=" * 75)
    print("ALL CONTEXT RISK TESTS PASSED")
    print("=" * 75)

    print("Results saved to:", OUTPUT_DIR)

    print(

        "No incident responses were executed."
    )

    print(

        "Reserved test dataset remains unevaluated."
    )


if __name__ == "__main__":

    main()