
from pathlib import Path
import urllib.request
import urllib.error
import json
import time
import math
import pandas as pd

BASE_URL = "http://127.0.0.1:8000"


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


def counts():

    return (
        request(
            "/api/multiclass/incidents?limit=1"
        )["total"],

        request(
            "/api/persistent-responses?limit=1"
        )["total"],
    )


model = request("/api/multiclass/model-info")

features = model["features"]

assert len(features) == 36

print("PASS: Model feature schema")

before = counts()

folder = Path(
    "results/multiclass/batch_test_datasets"
)

seven = pd.read_csv(
    folder / "seven_attack_samples.csv"
)

hundred = pd.read_csv(
    folder / "batch_test_100.csv"
)

large = pd.read_csv(
    folder / "batch_test_2500.csv"
)

results = []

test_batches = [
    seven.head(1),
    seven,
    hundred,
    large.head(1000),
]

for frame in test_batches:

    records = frame[features].to_dict("records")

    started = time.perf_counter()

    result = request(
        "/api/multiclass/predict-batch",
        {
            "records": records,
            "source": "stage_5_batch_verification",
        },
    )

    elapsed = time.perf_counter() - started

    predictions = result["predictions"]

    assert result["total_records"] == len(records)
    assert len(predictions) == len(records)

    for prediction in predictions:

        probability = prediction["attack_probability"]

        assert math.isfinite(probability)
        assert 0 <= probability <= 1

        assert (
            prediction["model_version"]
            == model["model_version"]
        )

        assert math.isclose(
            sum(
                prediction["class_probabilities"].values()
            ),
            1.0,
            abs_tol=1e-6,
        )

    results.append({
        "records": len(records),
        "elapsed_seconds": elapsed,
        "records_per_second": len(records) / elapsed,
    })

    print(
        f"PASS: {len(records)} records | "
        f"{elapsed:.3f} seconds | "
        f"{len(records) / elapsed:.2f} records/sec"
    )

# Verify invalid input rejection
invalid = seven.iloc[0][features].to_dict()

invalid.pop(features[0])

try:

    request(
        "/api/multiclass/predict-batch",
        {
            "records": [invalid],
            "source": "stage_5_invalid_test",
        },
    )

    raise AssertionError(
        "Invalid record was accepted"
    )

except urllib.error.HTTPError as error:

    assert error.code == 422, error.code

    print("PASS: Invalid feature rejection")

# Verify prediction-only operation
assert counts() == before

print(
    "PASS: Persistent incident and response counts unchanged"
)

# Verify assistant statistics endpoint
summary = request(
    "/api/multiclass/incidents/summary"
)

for field in [
    "total_incidents",
    "active_incidents",
    "active_critical_incidents",
    "resolved_incidents",
]:

    assert field in summary
    assert isinstance(summary[field], int)
    assert summary[field] >= 0

print("PASS: Security assistant incident statistics API")

# Save verification results
destination = Path(
    "results/multiclass/stage_5_batch"
)

destination.mkdir(
    parents=True,
    exist_ok=True,
)

output = {
    "batch_tests": results,
    "incident_summary": summary,
    "persistent_counts_unchanged": True,
    "invalid_input_rejected": True,
}

(destination / "verification_results.json").write_text(
    json.dumps(output, indent=2),
    encoding="utf-8",
)

print("=" * 60)
print("PASS: All batch prediction tests")
print("PASS: Security assistant API verification")
print("PASS: Verification results saved")
print("=" * 60)
