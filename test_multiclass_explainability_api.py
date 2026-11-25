from pathlib import Path
import math

import pandas as pd
import requests


BASE_URL = (
    "http://127.0.0.1:8000/api/multiclass"
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
    print("MULTICLASS SHAP API TEST")
    print("=" * 75)

    response = requests.get(
        f"{BASE_URL}/model-info",
        timeout=30,
    )

    response.raise_for_status()

    feature_names = response.json()[
        "features"
    ]

    df = pd.read_csv(
        DATA_PATH,
        usecols=feature_names + [
            "Label",
            "AttackFamily",
        ],
    )

    samples = (
        df.groupby("Label")
        .head(1)
        .sort_values("Label")
    )

    first_features = None

    for _, row in samples.iterrows():

        features = {
            name: float(row[name])
            for name in feature_names
        }

        if first_features is None:

            first_features = features.copy()

        response = requests.post(

            f"{BASE_URL}/explain",

            json={

                "features": features,

                "top_n": 5,

                "source": "shap_api_test",
            },

            timeout=120,
        )

        response.raise_for_status()

        result = response.json()

        prediction = result[
            "prediction"
        ]

        family = result[
            "family_explanation"
        ]

        attack = result[
            "attack_explanation"
        ]

        assert result[
            "additivity_verification"
        ]["passed"]

        assert result[
            "incident_created"
        ] is False

        assert result[
            "response_executed"
        ] is False

        assert len(
            family["top_features"]
        ) == 5

        assert len(
            attack["top_features"]
        ) == 5

        assert math.isclose(

            attack[
                "reconstructed_probability"
            ],

            prediction[
                "raw_attack_probability"
            ],

            abs_tol=1e-5,
            rel_tol=0,
        )

        print("\n" + "-" * 75)

        print(
            "Actual:",
            row["AttackFamily"],
        )

        print(
            "Predicted:",
            prediction["predicted_family"],
        )

        print(
            "Explained family:",
            result["explained_family"],
        )

        print(
            "Additivity: PASSED"
        )

        print(
            "Latency:",
            f"{result['total_latency_ms']:.2f} ms",
        )

        print(
            "HTTP status:",
            response.status_code,
        )

        print("\nTop attack contributions:")

        for item in attack["top_features"]:

            print(
                f"  {item['feature']:22s} "
                f"{item['shap_value']:+.6f}"
            )

    # ----------------------------------------------
    # EXPLICIT CLASS EXPLANATION
    # ----------------------------------------------

    response = requests.post(

        f"{BASE_URL}/explain",

        json={

            "features": first_features,

            "target_class": 4,

            "top_n": 5,
        },

        timeout=120,
    )

    response.raise_for_status()

    result = response.json()

    assert result["explained_family"] == (
        "BruteForce"
    )

    assert result[
        "additivity_verification"
    ]["passed"]

    print("\nExplicit class explanation: PASSED")

    # ----------------------------------------------
    # INVALID INPUT TESTS
    # ----------------------------------------------

    invalid_payloads = [

        {
            "features": first_features,
            "top_n": 0,
        },

        {
            "features": first_features,
            "top_n": 37,
        },

        {
            "features": first_features,
            "top_n": True,
        },

        {
            "features": first_features,
            "target_class": 8,
        },

        {
            "features": first_features,
            "target_class": True,
        },

        {
            "features": {},
        },
    ]

    print("\nINVALID INPUT TESTS")

    for index, payload in enumerate(
        invalid_payloads,
        start=1,
    ):

        response = requests.post(

            f"{BASE_URL}/explain",

            json=payload,

            timeout=30,
        )

        assert response.status_code == 422, (
            f"Invalid input test {index} failed."
        )

        print(
            f"Invalid input {index}: "
            f"PASSED (HTTP 422)"
        )

    print("\n" + "=" * 75)
    print("ALL MULTICLASS SHAP API TESTS PASSED")
    print("=" * 75)


if __name__ == "__main__":
    main()