from pathlib import Path
import json
import math

import pandas as pd
import numpy as np

from backend.app.multiclass_ml_service import (
    predict_traffic,
    predict_batch,
    get_model_info,
    FEATURE_NAMES,
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


def main():

    print("=" * 75)
    print("MULTICLASS ML SERVICE TEST")
    print("=" * 75)

    print("\nMODEL INFORMATION")

    print(
        json.dumps(
            get_model_info(),
            indent=4,
        )
    )

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

    # Select one example per supported class.

    samples = (
        df.groupby("Label", sort=True)
        .head(1)
        .sort_values("Label")
    )

    records = []

    individual_results = []

    for _, row in samples.iterrows():

        features = {
            name: float(row[name])
            for name in FEATURE_NAMES
        }

        records.append(features)

        result = predict_traffic(
            features
        )

        individual_results.append(result)

        print("\n" + "=" * 75)

        print(
            "Actual family:",
            row["AttackFamily"]
        )

        print(
            json.dumps(
                result,
                indent=4,
            )
        )

        assert 0 <= result[
            "attack_probability"
        ] <= 1

        assert len(
            result["class_probabilities"]
        ) == 8

        assert math.isclose(
            sum(
                result[
                    "class_probabilities"
                ].values()
            ),
            1.0,
            abs_tol=1e-6,
        )

        assert result[
            "high_confidence_alert"
        ] == (
            result["attack_probability"]
            >= 0.90
        )

    print("\nBATCH PREDICTION TEST")

    batch_results = predict_batch(
        records
    )

    assert len(batch_results) == len(records)

    for single, batch in zip(
        individual_results,
        batch_results,
    ):

        assert single[
            "predicted_label"
        ] == batch[
            "predicted_label"
        ]

        assert np.isclose(
            single["attack_probability"],
            batch["attack_probability"],
        )

    print("Batch prediction: PASSED")

    print("\nINPUT VALIDATION TESTS")

    invalid_inputs = {}

    missing_feature = records[0].copy()

    missing_feature.pop(
        FEATURE_NAMES[0]
    )

    invalid_inputs[
        "Missing feature"
    ] = missing_feature

    extra_feature = records[0].copy()

    extra_feature["unknown_feature"] = 100

    invalid_inputs[
        "Unexpected feature"
    ] = extra_feature

    invalid_numeric = records[0].copy()

    invalid_numeric[
        FEATURE_NAMES[0]
    ] = "invalid"

    invalid_inputs[
        "Non-numeric value"
    ] = invalid_numeric

    invalid_infinity = records[0].copy()

    invalid_infinity[
        FEATURE_NAMES[0]
    ] = float("inf")

    invalid_inputs[
        "Infinite value"
    ] = invalid_infinity

    invalid_nan = records[0].copy()

    invalid_nan[
        FEATURE_NAMES[0]
    ] = float("nan")

    invalid_inputs[
        "NaN value"
    ] = invalid_nan

    invalid_boolean = records[0].copy()

    invalid_boolean[
        FEATURE_NAMES[0]
    ] = True

    invalid_inputs[
        "Boolean value"
    ] = invalid_boolean

    for name, features in invalid_inputs.items():

        try:

            predict_traffic(features)

        except ValueError as error:

            print(
                f"{name}: PASSED"
            )

            print(
                f"  Rejected: {error}"
            )

        else:

            raise AssertionError(
                f"{name}: FAILED"
            )

    print("\n" + "=" * 75)
    print("ALL SERVICE TESTS PASSED")
    print("=" * 75)

    print(
        "The original backend service "
        "has not been modified."
    )

    print(
        "The reserved test dataset "
        "has not been evaluated."
    )


if __name__ == "__main__":
    main()