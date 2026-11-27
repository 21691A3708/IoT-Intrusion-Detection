
from pathlib import Path
import json
import math
import urllib.request
import urllib.error
import uuid

BASE_URL = "http://127.0.0.1:8000"

TOLERANCE = 1e-8

SOURCE = f"context_regression_{uuid.uuid4().hex}"

SAMPLE_DIR = Path(
    "results/multiclass/frontend_detection_samples"
)

OUTPUT_DIR = Path(
    "results/multiclass/context_comparison_api"
)

FAMILIES = [
    "benign",
    "ddos",
    "dos",
    "reconnaissance",
    "spoofing",
    "mirai",
    "webbased",
]


def request(path, payload=None):

    data = None

    if payload is not None:

        data = json.dumps(
            payload,
            allow_nan=False,
        ).encode("utf-8")

    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={
            "Content-Type": "application/json"
        },
        method="POST" if payload is not None else "GET",
    )

    with urllib.request.urlopen(
        req,
        timeout=120,
    ) as response:

        return json.load(response)


def near(a, b):

    return math.isclose(
        a,
        b,
        rel_tol=0,
        abs_tol=TOLERANCE,
    )


def compare_values(expected, actual, path="result"):

    if isinstance(expected, dict):

        assert isinstance(actual, dict), path

        assert expected.keys() == actual.keys(), (
            f"Different keys at {path}"
        )

        for key in expected:

            compare_values(
                expected[key],
                actual[key],
                f"{path}.{key}",
            )

    elif isinstance(expected, list):

        assert isinstance(actual, list), path
        assert len(expected) == len(actual), path

        for index, (a, b) in enumerate(
            zip(expected, actual)
        ):

            compare_values(
                a,
                b,
                f"{path}[{index}]",
            )

    elif isinstance(expected, float):

        assert isinstance(actual, (int, float)), path
        assert not isinstance(actual, bool), path

        assert math.isfinite(expected), path
        assert math.isfinite(actual), path

        assert near(expected, actual), (
            f"Mismatch at {path}: "
            f"{expected} != {actual}"
        )

    else:

        assert type(expected) is type(actual), path

        assert expected == actual, (
            f"Mismatch at {path}: "
            f"{expected} != {actual}"
        )


def persistent_counts():

    return {
        "incidents": request(
            "/api/multiclass/incidents?limit=1"
        )["total"],

        "responses": request(
            "/api/persistent-responses?limit=1"
        )["total"],
    }


def verify_safety(result):

    assert result["incident_created"] is False
    assert result["response_executed"] is False


def main():

    print("=" * 65)
    print("CONTEXT COMPARISON REGRESSION TEST")
    print("=" * 65)

    before = persistent_counts()

    model = request(
        "/api/multiclass/model-info"
    )

    feature_names = model["features"]

    assert len(feature_names) == 36

    print("PASS: Model feature schema")

    results = []

    comparison_count = 0

    for family in FAMILIES:

        sample_path = SAMPLE_DIR / f"{family}.json"

        features = json.loads(
            sample_path.read_text(
                encoding="utf-8-sig"
            )
        )

        assert set(features) == set(feature_names)

        result = request(
            "/api/multiclass/compare-contexts",
            {
                "features": features,
                "source": SOURCE,
            },
        )

        assert result["mode"] == "context_comparison_only"
        assert result["source"] == SOURCE
        assert result["simulation_only"] is True
        assert result["containment_authorized"] is False

        verify_safety(result)

        comparisons = result["comparisons"]

        assert result["total_contexts"] == 6
        assert len(comparisons) == 6

        expected_ids = {
            "sensor-001",
            "camera-001",
            "gateway-001",
            "medical-001",
            "industrial-001",
            None,
        }

        actual_ids = {
            row["device_id"]
            for row in comparisons
        }

        assert actual_ids == expected_ids

        scores = [
            row["risk_score"]
            for row in comparisons
        ]

        assert all(
            math.isfinite(score)
            and 0 <= score <= 100
            for score in scores
        )

        assert all(
            a + TOLERANCE >= b
            for a, b in zip(scores, scores[1:])
        )

        summary = result["summary"]

        assert near(
            summary["highest_risk_score"],
            max(scores),
        )

        assert near(
            summary["lowest_risk_score"],
            min(scores),
        )

        assert near(
            summary["risk_score_difference"],
            max(scores) - min(scores),
        )

        # Compare each context with the individual API.
        for row in comparisons:

            individual = request(
                "/api/multiclass/assess-risk",
                {
                    "features": features,
                    "device_id": row["device_id"],
                    "source": SOURCE,
                },
            )

            verify_safety(individual)

            compare_values(
                result["prediction"],
                individual["prediction"],
                "prediction",
            )

            assessment = individual["risk_assessment"]

            comparison_assessment = {
                key: row[key]
                for key in assessment
            }

            compare_values(
                assessment,
                comparison_assessment,
                "risk_assessment",
            )

            assert row["containment_authorized"] is False
            assert row["response_executed"] is False

            comparison_count += 1

        results.append({
            "sample_family": family,
            "predicted_family": (
                result["prediction"]["predicted_family"]
            ),
            "highest_risk": max(scores),
            "lowest_risk": min(scores),
            "risk_difference": max(scores) - min(scores),
            "contexts_verified": len(comparisons),
        })

        print(
            f"PASS: {family:16s} | "
            f"Contexts: {len(comparisons)} | "
            f"Risk: {min(scores):.2f} - {max(scores):.2f}"
        )

    # Invalid input verification
    valid = json.loads(
        (SAMPLE_DIR / "mirai.json").read_text(
            encoding="utf-8-sig"
        )
    )

    missing_feature = valid.copy()
    missing_feature.pop(feature_names[0])

    invalid_number = valid.copy()
    invalid_number[feature_names[0]] = "invalid"

    extra_feature = valid.copy()
    extra_feature["unexpected_feature"] = 123

    invalid_cases = [
        ("missing feature", missing_feature),
        ("invalid numeric value", invalid_number),
        ("unexpected feature", extra_feature),
        ("empty features", {}),
    ]

    for name, features in invalid_cases:

        try:

            request(
                "/api/multiclass/compare-contexts",
                {
                    "features": features,
                    "source": SOURCE,
                },
            )

        except urllib.error.HTTPError as error:

            assert error.code == 422, (
                name,
                error.code,
            )

            print(f"PASS: Rejected {name}")

        else:

            raise AssertionError(
                f"Invalid input accepted: {name}"
            )

    # Verify original prediction endpoint.
    prediction = request(
        "/api/multiclass/predict",
        {
            "features": valid,
            "source": SOURCE,
        },
    )

    verify_safety(prediction)

    assert (
        prediction["model_version"]
        == model["model_version"]
    )

    print("PASS: Original prediction API regression")

    after = persistent_counts()

    assert before == after, (
        f"Persistent counts changed: "
        f"{before} -> {after}"
    )

    print("PASS: Persistent counts unchanged")

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "source": SOURCE,
        "model_version": model["model_version"],
        "samples_verified": len(results),
        "context_assessments_verified": comparison_count,
        "invalid_cases_rejected": len(invalid_cases),
        "persistent_counts_before": before,
        "persistent_counts_after": after,
        "persistent_counts_unchanged": True,
        "results": results,
    }

    destination = (
        OUTPUT_DIR / "final_regression_results.json"
    )

    destination.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    print("=" * 65)
    print("PASS: ALL CONTEXT COMPARISON REGRESSION TESTS")
    print(f"Samples verified: {len(results)}")
    print(f"Context assessments: {comparison_count}")
    print(f"Invalid cases rejected: {len(invalid_cases)}")
    print(f"Results saved: {destination}")
    print("=" * 65)


if __name__ == "__main__":

    main()
