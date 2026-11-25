from pathlib import Path
import json

import numpy as np
import pandas as pd

from backend.app.multiclass_ml_service import (
    FEATURE_NAMES,
)

from backend.app.multiclass_explainability_service import (
    explain_prediction,
)


PROJECT_ROOT = Path(__file__).resolve().parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "multiclass"
    / "verified"
    / "validation.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "multiclass"
    / "explainability"
)


def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 75)
    print("MULTICLASS SHAP EXPLAINABILITY TEST")
    print("=" * 75)

    df = pd.read_csv(
        DATA_PATH,
        usecols=FEATURE_NAMES + [
            "Label",
            "AttackFamily",
        ],
        dtype={
            name: "float32"
            for name in FEATURE_NAMES
        },
    )

    samples = (
        df.groupby("Label")
        .head(1)
        .sort_values("Label")
    )

    summaries = []
    full_results = []

    first_features = None

    for _, row in samples.iterrows():

        features = {
            name: float(row[name])
            for name in FEATURE_NAMES
        }

        if first_features is None:

            first_features = features.copy()

        result = explain_prediction(
            features,
            top_n=5,
        )

        prediction = result["prediction"]

        family = result[
            "family_explanation"
        ]

        attack = result[
            "attack_explanation"
        ]

        verification = result[
            "additivity_verification"
        ]

        assert verification["passed"]

        assert result["shap_output_shape"] == [
            1, 36, 8
        ]

        assert len(
            family["all_features"]
        ) == 36

        assert len(
            attack["all_features"]
        ) == 36

        assert len(
            family["top_features"]
        ) == 5

        assert np.isclose(

            family[
                "reconstructed_probability"
            ],

            prediction[
                "prediction_confidence"
            ],

            atol=1e-5,
            rtol=0,
        )

        assert np.isclose(

            attack[
                "reconstructed_probability"
            ],

            prediction[
                "raw_attack_probability"
            ],

            atol=1e-5,
            rtol=0,
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
            "SHAP output shape:",
            result["shap_output_shape"],
        )

        print(
            "Family probability:",
            f"{family['target_probability']:.8f}",
        )

        print(
            "Family reconstruction:",
            f"{family['reconstructed_probability']:.8f}",
        )

        print(
            "Raw attack probability:",
            f"{attack['target_probability']:.8f}",
        )

        print(
            "Attack reconstruction:",
            f"{attack['reconstructed_probability']:.8f}",
        )

        print(
            "Calibrated attack probability:",
            f"{result['calibrated_attack_probability']:.8f}",
        )

        print(
            "Maximum additivity error:",
            f"{verification['maximum_class_error']:.10f}",
        )

        print(
            "SHAP latency:",
            f"{result['shap_latency_ms']:.2f} ms",
        )

        print("\nTOP FAMILY CONTRIBUTIONS")

        for item in family["top_features"]:

            print(
                f"{item['feature']:22s} "
                f"{item['shap_value']:+.8f}"
            )

        print("\nTOP OVERALL ATTACK CONTRIBUTIONS")

        for item in attack["top_features"]:

            print(
                f"{item['feature']:22s} "
                f"{item['shap_value']:+.8f}"
            )

        summaries.append({

            "ActualFamily":
                row["AttackFamily"],

            "PredictedFamily":
                prediction["predicted_family"],

            "FamilyProbability":
                family["target_probability"],

            "RawAttackProbability":
                attack["target_probability"],

            "CalibratedAttackProbability":
                result[
                    "calibrated_attack_probability"
                ],

            "FamilyAdditivityError":
                family["additivity_error"],

            "AttackAdditivityError":
                attack["additivity_error"],

            "MaximumClassError":
                verification[
                    "maximum_class_error"
                ],

            "SHAPLatencyMs":
                result["shap_latency_ms"],

            "TotalLatencyMs":
                result["total_latency_ms"],
        })

        full_results.append({

            "actual_family":
                row["AttackFamily"],

            "result":
                result,
        })

    # ----------------------------------------------
    # EXPLICIT TARGET CLASS TEST
    # ----------------------------------------------

    print("\nEXPLICIT TARGET CLASS TEST")

    selected = explain_prediction(
        first_features,
        top_n=5,
        target_class=4,
    )

    assert selected["explained_label"] == 4

    assert selected["explained_family"] == (
        "BruteForce"
    )

    assert selected[
        "additivity_verification"
    ]["passed"]

    assert np.isclose(

        selected[
            "family_explanation"
        ]["target_probability"],

        selected[
            "prediction"
        ]["class_probabilities"]["BruteForce"],

        atol=1e-5,
        rtol=0,
    )

    print("Explicit target class: PASSED")

    # ----------------------------------------------
    # INVALID INPUT TESTS
    # ----------------------------------------------

    print("\nINPUT VALIDATION TESTS")

    invalid_cases = [

        {"top_n": 0},

        {"top_n": 37},

        {"top_n": True},

        {"target_class": 8},

        {"target_class": -1},

        {"target_class": True},
    ]

    for arguments in invalid_cases:

        try:

            explain_prediction(
                first_features,
                **arguments,
            )

        except ValueError:

            print(
                f"{arguments}: PASSED"
            )

        else:

            raise AssertionError(
                f"{arguments}: FAILED"
            )

    # ----------------------------------------------
    # SAVE RESULTS
    # ----------------------------------------------

    summary_df = pd.DataFrame(
        summaries
    )

    summary_df.to_csv(
        OUTPUT_DIR / "shap_test_summary.csv",
        index=False,
    )

    with open(
        OUTPUT_DIR / "sample_explanations.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            full_results,
            file,
            indent=4,
        )

    print("\n" + "=" * 75)
    print("SHAP TEST SUMMARY")
    print("=" * 75)

    print(
        summary_df.to_string(
            index=False
        )
    )

    print(
        "\nMean SHAP latency:",
        f"{summary_df['SHAPLatencyMs'].mean():.2f} ms",
    )

    print(
        "Maximum additivity error:",
        summary_df["MaximumClassError"].max(),
    )

    print("\n" + "=" * 75)
    print("ALL MULTICLASS SHAP TESTS PASSED")
    print("=" * 75)

    print(
        "Results saved to:",
        OUTPUT_DIR,
    )

    print(
        "The reserved test dataset "
        "has not been evaluated."
    )


if __name__ == "__main__":
    main()