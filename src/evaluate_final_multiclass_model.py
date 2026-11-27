
from pathlib import Path
from datetime import datetime, timezone
from time import perf_counter

import sys
import json
import hashlib

import joblib
import numpy as np
import pandas as pd

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    roc_curve,
    precision_recall_curve,
    brier_score_loss,
    log_loss,
)

from sklearn.calibration import calibration_curve


# ==================================================
# 1. CONFIGURATION
# ==================================================

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "backend"))

from app.calibration_service import (
    calibrate_attack_probability
)

MODEL_PATH = (
    ROOT / "models"
    / "random_forest_multiclass_calibrated.joblib"
)

TEST_PATH = (
    ROOT / "data/processed/multiclass/verified/test.csv"
)

OUTPUT_DIR = (
    ROOT / "results/multiclass/final_evaluation"
)

GRAPH_DIR = OUTPUT_DIR / "graphs"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
GRAPH_DIR.mkdir(parents=True, exist_ok=True)

BATCH_SIZE = 10000

ALERT_THRESHOLD = 0.90

RANDOM_STATE = 42

plt.rcParams.update({
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
    "figure.dpi": 120,
    "savefig.dpi": 300,
})


def save_json(filename, data):

    destination = OUTPUT_DIR / filename

    destination.write_text(
        json.dumps(
            data,
            indent=2,
            allow_nan=False,
        ),
        encoding="utf-8",
    )


def save_graph(filename):

    destination = GRAPH_DIR / filename

    plt.tight_layout()

    plt.savefig(
        destination,
        dpi=300,
        bbox_inches="tight",
    )

    plt.close()

    print(f"Saved graph: {filename}")


def file_hash(path):

    digest = hashlib.sha256()

    with path.open("rb") as file:

        for block in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):

            digest.update(block)

    return digest.hexdigest()


def divide(a, b):

    return float(a / b) if b else 0.0


# ==================================================
# 2. LOAD MODEL
# ==================================================

print("=" * 70)
print("IOT SENTINEL - FINAL HELD-OUT MODEL EVALUATION")
print("=" * 70)

print("\n[1] LOADING TRAINED MODEL\n")

bundle = joblib.load(MODEL_PATH)

model = bundle["model"]

feature_names = list(bundle["feature_names"])

labels = {
    int(key): str(value)
    for key, value in bundle["labels"].items()
}

class_ids = sorted(labels)

class_names = [
    labels[class_id]
    for class_id in class_ids
]

calibration = bundle["calibration"]

model_version = bundle["model_version"]

model_classes = [
    int(value)
    for value in model.classes_
]

assert len(feature_names) == 36

assert set(model_classes) == set(class_ids)

assert labels[0] == "Benign"

assert bundle["calibrated"] is True

benign_position = model_classes.index(0)

ordered_positions = [
    model_classes.index(class_id)
    for class_id in class_ids
]

print(f"Model version : {model_version}")
print(f"Features      : {len(feature_names)}")
print(f"Classes       : {class_names}")

print("PASS: Model loaded successfully")


# ==================================================
# 3. LOAD HELD-OUT TEST DATA
# ==================================================

print("\n[2] LOADING HELD-OUT TEST DATA\n")

dataset = pd.read_csv(
    TEST_PATH,
    dtype={
        feature: np.float32
        for feature in feature_names
    },
)

required_columns = set(
    feature_names + [
        "Label",
        "AttackFamily",
        "OriginalAttack",
        "SourceCapture",
    ]
)

assert required_columns.issubset(
    dataset.columns
)

X = dataset[feature_names]

y_true = dataset["Label"].to_numpy(
    dtype=np.int64
)

assert len(dataset) > 0

assert np.isfinite(
    X.to_numpy()
).all()

assert set(np.unique(y_true)).issubset(
    class_ids
)

expected_families = pd.Series(
    y_true
).map(labels).to_numpy()

assert np.array_equal(
    expected_families,
    dataset["AttackFamily"].to_numpy(),
)

supported_labels = sorted(
    int(value)
    for value in np.unique(y_true)
)

unsupported_labels = [
    class_id
    for class_id in class_ids
    if class_id not in supported_labels
]

print(f"Total test records: {len(dataset):,}")

print("\nClass distribution:")

for class_id in class_ids:

    support = int(
        np.sum(y_true == class_id)
    )

    print(
        f"{labels[class_id]:18s}: "
        f"{support:,}"
    )

print(
    "\nUnsupported test classes:",
    [
        labels[class_id]
        for class_id in unsupported_labels
    ],
)

print("PASS: Held-out dataset verified")


# ==================================================
# 4. MULTICLASS INFERENCE
# ==================================================

print("\n[3] RUNNING MULTICLASS INFERENCE\n")

probability_batches = []

batch_times = []

start_time = perf_counter()

for start in range(
    0,
    len(X),
    BATCH_SIZE,
):

    end = min(
        start + BATCH_SIZE,
        len(X),
    )

    batch = X.iloc[start:end]

    batch_start = perf_counter()

    probabilities = model.predict_proba(
        batch
    )

    elapsed = perf_counter() - batch_start

    probability_batches.append(
        probabilities
    )

    batch_times.append({
        "records": len(batch),
        "seconds": elapsed,
        "records_per_second": (
            len(batch) / elapsed
        ),
    })

    print(
        f"Processed {end:,}/{len(X):,} "
        f"records | {elapsed:.3f} sec"
    )

total_inference_time = (
    perf_counter() - start_time
)

probabilities = np.vstack(
    probability_batches
)

assert probabilities.shape == (
    len(X),
    len(class_ids),
)

assert np.isfinite(probabilities).all()

assert np.allclose(
    probabilities.sum(axis=1),
    1.0,
    atol=1e-8,
)

y_pred = np.asarray(
    model_classes
)[np.argmax(probabilities, axis=1)]

raw_attack_probability = np.clip(
    1.0 - probabilities[:, benign_position],
    0.0,
    1.0,
)

calibration_start = perf_counter()

calibrated_attack_probability = np.asarray([
    calibrate_attack_probability(
        float(probability),
        calibration,
    )
    for probability in raw_attack_probability
])

calibration_time = (
    perf_counter() - calibration_start
)

assert np.isfinite(
    calibrated_attack_probability
).all()

assert np.all(
    (calibrated_attack_probability >= 0)
    & (calibrated_attack_probability <= 1)
)

y_binary = (
    y_true != 0
).astype(int)

print("\nPASS: All predictions generated")

print(
    f"Inference time: "
    f"{total_inference_time:.3f} seconds"
)

print(
    f"Throughput: "
    f"{len(X) / total_inference_time:.2f} "
    "records/sec"
)


# ==================================================
# 5. MULTICLASS CLASSIFICATION METRICS
# ==================================================

print("\n[4] MULTICLASS CLASSIFICATION METRICS\n")

multiclass_metrics = {

    "accuracy": float(
        accuracy_score(y_true, y_pred)
    ),

    "balanced_accuracy": float(
        balanced_accuracy_score(
            y_true,
            y_pred,
        )
    ),

    "macro_precision_supported": float(
        precision_score(
            y_true,
            y_pred,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        )
    ),

    "macro_recall_supported": float(
        recall_score(
            y_true,
            y_pred,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        )
    ),

    "macro_f1_supported": float(
        f1_score(
            y_true,
            y_pred,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        )
    ),

    "weighted_f1": float(
        f1_score(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0,
        )
    ),

    "multiclass_log_loss": float(
        log_loss(
            y_true,
            probabilities[:, ordered_positions],
            labels=class_ids,
        )
    ),

    "supported_labels": supported_labels,

    "unsupported_labels": unsupported_labels,
}

for key, value in multiclass_metrics.items():

    if isinstance(value, float):

        print(f"{key:30s}: {value:.6f}")

report = classification_report(
    y_true,
    y_pred,
    labels=class_ids,
    target_names=class_names,
    output_dict=True,
    zero_division=0,
)

family_rows = []

for class_id in class_ids:

    family = labels[class_id]

    metrics = report[family]

    supported = metrics["support"] > 0

    family_rows.append({
        "class_id": class_id,
        "attack_family": family,
        "precision": (
            metrics["precision"]
            if supported else None
        ),
        "recall": (
            metrics["recall"]
            if supported else None
        ),
        "f1_score": (
            metrics["f1-score"]
            if supported else None
        ),
        "support": int(metrics["support"]),
        "predicted_count": int(
            np.sum(y_pred == class_id)
        ),
        "test_supported": supported,
    })

family_metrics = pd.DataFrame(
    family_rows
)

family_metrics.to_csv(
    OUTPUT_DIR / "per_family_metrics.csv",
    index=False,
)

print("\nPer-family results:")

print(
    family_metrics.to_string(index=False)
)

matrix = confusion_matrix(
    y_true,
    y_pred,
    labels=class_ids,
)

pd.DataFrame(
    matrix,
    index=class_names,
    columns=class_names,
).to_csv(
    OUTPUT_DIR / "confusion_matrix.csv"
)


# ==================================================
# 6. BINARY INTRUSION DETECTION
# ==================================================

print("\n[5] BINARY INTRUSION DETECTION\n")


def binary_metrics(predictions):

    tn, fp, fn, tp = confusion_matrix(
        y_binary,
        predictions,
        labels=[0, 1],
    ).ravel()

    return {
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),

        "accuracy": float(
            accuracy_score(
                y_binary,
                predictions,
            )
        ),

        "precision": divide(tp, tp + fp),

        "recall": divide(tp, tp + fn),

        "f1_score": float(
            f1_score(
                y_binary,
                predictions,
                zero_division=0,
            )
        ),

        "false_positive_rate": divide(
            fp,
            fp + tn,
        ),

        "false_negative_rate": divide(
            fn,
            fn + tp,
        ),

        "specificity": divide(
            tn,
            tn + fp,
        ),

        "alert_count": int(
            np.sum(predictions)
        ),
    }


binary_results = {

    "multiclass_argmax": binary_metrics(
        (y_pred != 0).astype(int)
    ),

    "raw_probability_0_50": binary_metrics(
        (
            raw_attack_probability >= 0.50
        ).astype(int)
    ),

    "calibrated_probability_0_50": binary_metrics(
        (
            calibrated_attack_probability >= 0.50
        ).astype(int)
    ),

    "raw_probability_0_90": binary_metrics(
        (
            raw_attack_probability
            >= ALERT_THRESHOLD
        ).astype(int)
    ),

    "calibrated_probability_0_90": binary_metrics(
        (
            calibrated_attack_probability
            >= ALERT_THRESHOLD
        ).astype(int)
    ),
}

for name, metrics in binary_results.items():

    print(f"\n{name}")

    for key, value in metrics.items():

        if isinstance(value, float):

            print(f"  {key:24s}: {value:.6f}")

        else:

            print(f"  {key:24s}: {value:,}")

pd.DataFrame([
    {
        "method": name,
        **metrics,
    }
    for name, metrics in binary_results.items()
]).to_csv(
    OUTPUT_DIR / "binary_detection_metrics.csv",
    index=False,
)


# ==================================================
# 7. PROBABILITY CALIBRATION EVALUATION
# ==================================================

print("\n[6] PROBABILITY CALIBRATION EVALUATION\n")


def expected_calibration_error(
    actual,
    probabilities,
    n_bins=10,
):

    edges = np.linspace(
        0,
        1,
        n_bins + 1,
    )

    assignments = np.digitize(
        probabilities,
        edges[1:-1],
    )

    error = 0.0

    for index in range(n_bins):

        mask = assignments == index

        if not np.any(mask):

            continue

        observed = np.mean(
            actual[mask]
        )

        confidence = np.mean(
            probabilities[mask]
        )

        weight = np.mean(mask)

        error += (
            weight
            * abs(observed - confidence)
        )

    return float(error)


def probability_metrics(probabilities):

    return {

        "roc_auc": float(
            roc_auc_score(
                y_binary,
                probabilities,
            )
        ),

        "average_precision": float(
            average_precision_score(
                y_binary,
                probabilities,
            )
        ),

        "brier_score": float(
            brier_score_loss(
                y_binary,
                probabilities,
            )
        ),

        "binary_log_loss": float(
            log_loss(
                y_binary,
                probabilities,
                labels=[0, 1],
            )
        ),

        "ece_10_bins": (
            expected_calibration_error(
                y_binary,
                probabilities,
            )
        ),
    }


calibration_results = {

    "raw": probability_metrics(
        raw_attack_probability
    ),

    "calibrated": probability_metrics(
        calibrated_attack_probability
    ),
}

for name, metrics in calibration_results.items():

    print(f"\n{name.upper()} PROBABILITIES")

    for key, value in metrics.items():

        print(f"{key:24s}: {value:.6f}")

pd.DataFrame([
    {
        "method": name,
        **metrics,
    }
    for name, metrics
    in calibration_results.items()
]).to_csv(
    OUTPUT_DIR / "calibration_metrics.csv",
    index=False,
)


# ==================================================
# 8. ALERT RECALL BY ATTACK FAMILY
# ==================================================

print("\n[7] HIGH-CONFIDENCE ALERT ANALYSIS\n")

alert_rows = []

for class_id in class_ids:

    mask = y_true == class_id

    support = int(np.sum(mask))

    alerts = int(np.sum(
        calibrated_attack_probability[mask]
        >= ALERT_THRESHOLD
    ))

    alert_rows.append({
        "attack_family": labels[class_id],
        "support": support,
        "alerts": alerts,
        "alert_rate": (
            divide(alerts, support)
            if support else None
        ),
        "threshold": ALERT_THRESHOLD,
    })

alert_metrics = pd.DataFrame(
    alert_rows
)

alert_metrics.to_csv(
    OUTPUT_DIR / "alert_rates_by_family.csv",
    index=False,
)

print(
    alert_metrics.to_string(index=False)
)


# ==================================================
# 9. INFERENCE LATENCY BENCHMARK
# ==================================================

print("\n[8] INFERENCE LATENCY BENCHMARK\n")

rng = np.random.default_rng(
    RANDOM_STATE
)

benchmark_indices = rng.choice(
    len(X),
    size=min(100, len(X)),
    replace=False,
)

# Warm-up prediction
model.predict_proba(X.iloc[[0]])

latencies = []

for index in benchmark_indices:

    sample = X.iloc[[index]]

    start = perf_counter()

    model.predict_proba(sample)

    latencies.append(
        (perf_counter() - start) * 1000
    )

performance = {
    "test_records": len(X),
    "batch_size": BATCH_SIZE,
    "total_inference_seconds": (
        total_inference_time
    ),
    "calibration_seconds": calibration_time,
    "inference_records_per_second": (
        len(X) / total_inference_time
    ),
    "single_record_samples": len(latencies),
    "single_record_mean_ms": float(
        np.mean(latencies)
    ),
    "single_record_median_ms": float(
        np.median(latencies)
    ),
    "single_record_p95_ms": float(
        np.percentile(latencies, 95)
    ),
    "single_record_max_ms": float(
        np.max(latencies)
    ),
}

for key, value in performance.items():

    print(f"{key:32s}: {value}")

pd.DataFrame(
    batch_times
).to_csv(
    OUTPUT_DIR / "batch_performance.csv",
    index=False,
)


# ==================================================
# 10. GENERATE RESEARCH GRAPHS
# ==================================================

print("\n[9] GENERATING RESEARCH GRAPHS\n")


# Graph 1: Confusion matrix

fig, ax = plt.subplots(
    figsize=(11, 9)
)

image = ax.imshow(
    matrix,
    cmap="Blues",
)

fig.colorbar(image, ax=ax)

ax.set_xticks(range(len(class_names)))
ax.set_yticks(range(len(class_names)))

ax.set_xticklabels(
    class_names,
    rotation=45,
    ha="right",
)

ax.set_yticklabels(class_names)

for i in range(len(class_names)):

    for j in range(len(class_names)):

        value = matrix[i, j]

        ax.text(
            j,
            i,
            f"{value:,}",
            ha="center",
            va="center",
            fontsize=9,
            color=(
                "white"
                if value > matrix.max() / 2
                else "black"
            ),
        )

ax.set_xlabel("Predicted attack family")
ax.set_ylabel("Actual attack family")

ax.set_title(
    "Multiclass Confusion Matrix - Held-Out Test"
)

save_graph("01_confusion_matrix.png")


# Graph 2: Normalized confusion matrix

row_totals = matrix.sum(
    axis=1,
    keepdims=True,
)

normalized = np.divide(
    matrix,
    row_totals,
    out=np.zeros_like(
        matrix,
        dtype=float,
    ),
    where=row_totals != 0,
)

fig, ax = plt.subplots(
    figsize=(11, 9)
)

image = ax.imshow(
    normalized,
    cmap="Blues",
    vmin=0,
    vmax=1,
)

fig.colorbar(image, ax=ax)

ax.set_xticks(range(len(class_names)))
ax.set_yticks(range(len(class_names)))

ax.set_xticklabels(
    class_names,
    rotation=45,
    ha="right",
)

ax.set_yticklabels(class_names)

for i in range(len(class_names)):

    for j in range(len(class_names)):

        value = normalized[i, j]

        label = (
            f"{value:.1%}"
            if row_totals[i, 0] > 0
            else "N/A"
        )

        ax.text(
            j,
            i,
            label,
            ha="center",
            va="center",
            fontsize=9,
            color=(
                "white"
                if value > 0.5
                else "black"
            ),
        )

ax.set_xlabel("Predicted attack family")
ax.set_ylabel("Actual attack family")

ax.set_title(
    "Normalized Multiclass Confusion Matrix"
)

save_graph("02_normalized_confusion_matrix.png")


# Graph 3: Per-family performance

supported = family_metrics[
    family_metrics["test_supported"]
]

positions = np.arange(len(supported))

width = 0.25

plt.figure(figsize=(12, 6))

plt.bar(
    positions - width,
    supported["precision"],
    width,
    label="Precision",
)

plt.bar(
    positions,
    supported["recall"],
    width,
    label="Recall",
)

plt.bar(
    positions + width,
    supported["f1_score"],
    width,
    label="F1-score",
)

plt.xticks(
    positions,
    supported["attack_family"],
    rotation=30,
    ha="right",
)

plt.ylim(0, 1.05)

plt.ylabel("Score")

plt.title(
    "Attack-Family Classification Performance"
)

plt.legend()

plt.grid(axis="y", alpha=0.25)

save_graph("03_per_family_performance.png")


# Graph 4: ROC curves

plt.figure(figsize=(8, 6))

for name, scores in [
    ("Raw", raw_attack_probability),
    ("Calibrated", calibrated_attack_probability),
]:

    fpr, tpr, _ = roc_curve(
        y_binary,
        scores,
    )

    auc = roc_auc_score(
        y_binary,
        scores,
    )

    plt.plot(
        fpr,
        tpr,
        label=f"{name} (AUC={auc:.4f})",
    )

plt.plot(
    [0, 1],
    [0, 1],
    "--",
    label="Random baseline",
)

plt.xlabel("False positive rate")
plt.ylabel("True positive rate")
plt.title("Binary Intrusion Detection ROC Curve")
plt.legend()
plt.grid(alpha=0.25)

save_graph("04_roc_curve.png")


# Graph 5: Precision-recall curves

plt.figure(figsize=(8, 6))

for name, scores in [
    ("Raw", raw_attack_probability),
    ("Calibrated", calibrated_attack_probability),
]:

    precision, recall, _ = (
        precision_recall_curve(
            y_binary,
            scores,
        )
    )

    ap = average_precision_score(
        y_binary,
        scores,
    )

    plt.plot(
        recall,
        precision,
        label=f"{name} (AP={ap:.4f})",
    )

plt.axhline(
    np.mean(y_binary),
    linestyle="--",
    label="Attack prevalence baseline",
)

plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title("Precision-Recall Curve")
plt.legend()
plt.grid(alpha=0.25)

save_graph("05_precision_recall_curve.png")


# Graph 6: Calibration reliability

plt.figure(figsize=(8, 6))

for name, scores in [
    ("Raw", raw_attack_probability),
    ("Calibrated", calibrated_attack_probability),
]:

    observed, predicted = calibration_curve(
        y_binary,
        scores,
        n_bins=10,
        strategy="uniform",
    )

    plt.plot(
        predicted,
        observed,
        marker="o",
        label=name,
    )

plt.plot(
    [0, 1],
    [0, 1],
    "--",
    label="Perfect calibration",
)

plt.xlabel("Mean predicted attack probability")
plt.ylabel("Observed attack frequency")
plt.title("Probability Calibration Reliability")
plt.legend()
plt.grid(alpha=0.25)

save_graph("06_calibration_curve.png")


# Graph 7: Calibration error comparison

metric_names = [
    "brier_score",
    "binary_log_loss",
    "ece_10_bins",
]

positions = np.arange(
    len(metric_names)
)

plt.figure(figsize=(9, 6))

plt.bar(
    positions - 0.18,
    [
        calibration_results["raw"][key]
        for key in metric_names
    ],
    0.36,
    label="Raw",
)

plt.bar(
    positions + 0.18,
    [
        calibration_results["calibrated"][key]
        for key in metric_names
    ],
    0.36,
    label="Calibrated",
)

plt.xticks(
    positions,
    ["Brier score", "Log loss", "ECE"],
)

plt.ylabel("Error (lower is better)")
plt.title("Raw vs Calibrated Probability Errors")
plt.legend()
plt.grid(axis="y", alpha=0.25)

save_graph("07_calibration_error_comparison.png")


# Graph 8: Threshold comparison

threshold_rows = []

for threshold in np.linspace(
    0.05,
    0.95,
    19,
):

    predictions = (
        calibrated_attack_probability
        >= threshold
    ).astype(int)

    metrics = binary_metrics(
        predictions
    )

    threshold_rows.append({
        "threshold": float(threshold),
        **metrics,
    })

threshold_df = pd.DataFrame(
    threshold_rows
)

threshold_df.to_csv(
    OUTPUT_DIR / "threshold_analysis.csv",
    index=False,
)

plt.figure(figsize=(10, 6))

for key, label in [
    ("precision", "Precision"),
    ("recall", "Recall"),
    ("f1_score", "F1-score"),
    ("false_positive_rate", "False positive rate"),
]:

    plt.plot(
        threshold_df["threshold"],
        threshold_df[key],
        marker="o",
        markersize=3,
        label=label,
    )

plt.axvline(
    ALERT_THRESHOLD,
    linestyle="--",
    label="Fixed alert threshold (0.90)",
)

plt.xlabel("Calibrated attack threshold")
plt.ylabel("Score")
plt.ylim(0, 1.05)

plt.title(
    "Detection Performance Across Thresholds"
)

plt.legend()
plt.grid(alpha=0.25)

save_graph("08_threshold_analysis.png")


# Graph 9: Alert rate by family

supported_alerts = alert_metrics[
    alert_metrics["support"] > 0
]

plt.figure(figsize=(11, 6))

plt.bar(
    supported_alerts["attack_family"],
    supported_alerts["alert_rate"],
)

plt.xticks(rotation=30, ha="right")
plt.ylim(0, 1.05)
plt.ylabel("High-confidence alert rate")

plt.title(
    "Alert Rate by Family at Threshold 0.90"
)

plt.grid(axis="y", alpha=0.25)

save_graph("09_alert_rate_by_family.png")


# Graph 10: Inference latency

plt.figure(figsize=(9, 6))

plt.hist(
    latencies,
    bins=20,
    edgecolor="black",
    alpha=0.8,
)

plt.axvline(
    performance["single_record_p95_ms"],
    linestyle="--",
    label=(
        "P95 = "
        f"{performance['single_record_p95_ms']:.2f} ms"
    ),
)

plt.xlabel("Inference latency (ms)")
plt.ylabel("Frequency")
plt.title("Single-Record Model Inference Latency")
plt.legend()
plt.grid(axis="y", alpha=0.25)

save_graph("10_inference_latency.png")


# ==================================================
# 11. SAVE PREDICTION RESULTS
# ==================================================

print("\n[10] SAVING EVALUATION RESULTS\n")

prediction_output = dataset[[
    "Label",
    "AttackFamily",
    "OriginalAttack",
    "SourceCapture",
]].copy()

prediction_output["PredictedLabel"] = y_pred

prediction_output["PredictedFamily"] = [
    labels[int(value)]
    for value in y_pred
]

prediction_output["RawAttackProbability"] = (
    raw_attack_probability
)

prediction_output["CalibratedAttackProbability"] = (
    calibrated_attack_probability
)

prediction_output["HighConfidenceAlert"] = (
    calibrated_attack_probability
    >= ALERT_THRESHOLD
)

prediction_output["CorrectClassification"] = (
    y_true == y_pred
)

prediction_output.to_csv(
    OUTPUT_DIR / "test_predictions.csv",
    index=False,
)

summary = {
    "generated_at": datetime.now(
        timezone.utc
    ).isoformat(),

    "model_version": model_version,

    "model_sha256": file_hash(
        MODEL_PATH
    ),

    "test_dataset_sha256": file_hash(
        TEST_PATH
    ),

    "evaluation_dataset": (
        "verified_held_out_test"
    ),

    "test_records": len(dataset),

    "test_capture_count": int(
        dataset["SourceCapture"].nunique()
    ),

    "feature_count": len(feature_names),

    "class_count": len(class_ids),

    "test_supported_classes": [
        labels[class_id]
        for class_id in supported_labels
    ],

    "test_unsupported_classes": [
        labels[class_id]
        for class_id in unsupported_labels
    ],

    "attack_prevalence": float(
        np.mean(y_binary)
    ),

    "alert_threshold": ALERT_THRESHOLD,

    "multiclass_metrics": multiclass_metrics,

    "per_family_metrics": family_rows,

    "binary_detection_metrics": binary_results,

    "calibration_metrics": calibration_results,

    "alert_rates_by_family": alert_rows,

    "performance": performance,

    "limitations": [
        "Evaluation uses the duplicate-filtered "
        "held-out test dataset.",

        "Unsupported classes are excluded from "
        "supported-class macro averages.",

        "Binary attack calibration does not "
        "calibrate individual family probabilities.",

        "Threshold analysis is descriptive and "
        "must not be used for test-set tuning.",

        "Latency measures local model inference, "
        "not end-to-end API latency.",

        "Dataset attack prevalence may differ "
        "substantially from deployment prevalence.",

        "Capture-level separation does not prove "
        "independent real-world network sessions.",
    ],
}

save_json(
    "final_evaluation_summary.json",
    summary,
)

print("\n" + "=" * 70)
print("FINAL MODEL EVALUATION SUMMARY")
print("=" * 70)

print(f"Model: {model_version}")

print(f"Test records: {len(dataset):,}")

print(
    "Accuracy: "
    f"{multiclass_metrics['accuracy']:.6f}"
)

print(
    "Balanced accuracy: "
    f"{multiclass_metrics['balanced_accuracy']:.6f}"
)

print(
    "Macro F1 (supported classes): "
    f"{multiclass_metrics['macro_f1_supported']:.6f}"
)

print(
    "Weighted F1: "
    f"{multiclass_metrics['weighted_f1']:.6f}"
)

print(
    "Calibrated ROC-AUC: "
    f"{calibration_results['calibrated']['roc_auc']:.6f}"
)

print(
    "Raw Brier score: "
    f"{calibration_results['raw']['brier_score']:.6f}"
)

print(
    "Calibrated Brier score: "
    f"{calibration_results['calibrated']['brier_score']:.6f}"
)

print(
    "Alert false positive rate: "
    f"{binary_results['calibrated_probability_0_90']['false_positive_rate']:.6f}"
)

print(
    "Alert recall: "
    f"{binary_results['calibrated_probability_0_90']['recall']:.6f}"
)

print(
    "Inference throughput: "
    f"{performance['inference_records_per_second']:.2f}"
    " records/sec"
)

print(
    "Single-record P95 latency: "
    f"{performance['single_record_p95_ms']:.3f} ms"
)

print(f"\nResults directory: {OUTPUT_DIR}")

print(f"Graphs directory: {GRAPH_DIR}")

print("=" * 70)
print("PASS: FINAL HELD-OUT EVALUATION COMPLETED")
print("=" * 70)
