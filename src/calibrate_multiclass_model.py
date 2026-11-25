from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

from sklearn.linear_model import LogisticRegression

from sklearn.calibration import calibration_curve

from sklearn.metrics import (
    brier_score_loss,
    log_loss,
    roc_auc_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "processed" / "multiclass"
)

MODEL_DIR = PROJECT_ROOT / "models"

RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
    / "multiclass"
    / "calibration"
)

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

INPUT_MODEL = (
    MODEL_DIR
    / "random_forest_multiclass_optimized.joblib"
)

OUTPUT_MODEL = (
    MODEL_DIR
    / "random_forest_multiclass_calibrated.joblib"
)

EPSILON = 1e-6


def probability_to_logit(probabilities):

    probabilities = np.clip(
        probabilities,
        EPSILON,
        1.0 - EPSILON,
    )

    return np.log(
        probabilities / (1.0 - probabilities)
    ).reshape(-1, 1)


def calculate_ece(y_true, probabilities, n_bins=10):

    y_true = np.asarray(y_true)

    probabilities = np.asarray(probabilities)

    boundaries = np.linspace(
        0.0, 1.0, n_bins + 1
    )

    ece = 0.0

    for index in range(n_bins):

        lower = boundaries[index]

        upper = boundaries[index + 1]

        if index == n_bins - 1:

            mask = (
                (probabilities >= lower)
                & (probabilities <= upper)
            )

        else:

            mask = (
                (probabilities >= lower)
                & (probabilities < upper)
            )

        if not mask.any():
            continue

        observed_frequency = y_true[mask].mean()

        predicted_probability = (
            probabilities[mask].mean()
        )

        weight = mask.sum() / len(y_true)

        ece += weight * abs(
            observed_frequency
            - predicted_probability
        )

    return float(ece)


def evaluate_probabilities(y_true, probabilities):

    return {
        "BrierScore": brier_score_loss(
            y_true, probabilities
        ),

        "BinaryLogLoss": log_loss(
            y_true,
            probabilities,
            labels=[0, 1],
        ),

        "ROC_AUC": roc_auc_score(
            y_true, probabilities
        ),

        "ECE": calculate_ece(
            y_true, probabilities
        ),
    }


def main():

    print("=" * 70)
    print("MULTICLASS ATTACK PROBABILITY CALIBRATION")
    print("=" * 70)

    bundle = joblib.load(INPUT_MODEL)

    model = bundle["model"]

    model.set_params(verbose=0)

    features = bundle["feature_names"]

    labels = bundle["labels"]

    with open(
        DATA_DIR / "feature_schema.json",
        encoding="utf-8",
    ) as file:

        expected_features = json.load(file)

    if features != expected_features:

        raise ValueError(
            "Feature schema mismatch."
        )

    print("\nModel configuration:")

    print(
        bundle.get("configuration", "Unknown")
    )

    print("Features:", len(features))

    print("Model classes:", model.classes_)

    # Only validation data is used here.
    # The reserved test dataset is not loaded.

    validation = pd.read_csv(
        DATA_DIR / "verified" / "validation.csv",
        usecols=features + ["Label"],
        dtype={
            feature: "float32"
            for feature in features
        },
    )

    X_val = validation[features]

    y_multiclass = validation["Label"].to_numpy()

    y_binary = (
        y_multiclass != 0
    ).astype(int)

    if set(np.unique(y_binary)) != {0, 1}:

        raise ValueError(
            "Calibration requires both benign "
            "and attack records."
        )

    print("\nCalibration records:", len(X_val))

    print(
        "Benign records:",
        int((y_binary == 0).sum()),
    )

    print(
        "Attack records:",
        int((y_binary == 1).sum()),
    )

    probabilities = model.predict_proba(X_val)

    class_positions = {
        int(label): index
        for index, label in enumerate(model.classes_)
    }

    benign_index = class_positions[0]

    raw_attack_probability = (
        1.0 - probabilities[:, benign_index]
    )

    print("\nFitting sigmoid calibrator...")

    calibration_input = probability_to_logit(
        raw_attack_probability
    )

    calibrator = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=42,
    )

    calibrator.fit(
        calibration_input,
        y_binary,
    )

    calibrated_attack_probability = (
        calibrator.predict_proba(
            calibration_input
        )[:, 1]
    )

    before = evaluate_probabilities(
        y_binary,
        raw_attack_probability,
    )

    after = evaluate_probabilities(
        y_binary,
        calibrated_attack_probability,
    )

    comparison = pd.DataFrame(
        [before, after],
        index=[
            "Uncalibrated",
            "Calibrated",
        ],
    )

    print("\n" + "=" * 70)
    print("CALIBRATION FIT DIAGNOSTICS")
    print("=" * 70)

    print(
        comparison.round(6).to_string()
    )

    print(
        "\nNOTE: These metrics are calculated "
        "on the calibration fitting data."
    )

    comparison.to_csv(
        RESULTS_DIR / "calibration_metrics.csv"
    )

    # Generate reliability diagram.

    fig, ax = plt.subplots(
        figsize=(8, 7)
    )

    ax.plot(
        [0, 1],
        [0, 1],
        linestyle="--",
        color="gray",
        label="Perfect calibration",
    )

    for name, values in [

        (
            "Uncalibrated",
            raw_attack_probability,
        ),

        (
            "Calibrated",
            calibrated_attack_probability,
        ),

    ]:

        observed, predicted = calibration_curve(
            y_binary,
            values,
            n_bins=10,
            strategy="uniform",
        )

        ax.plot(
            predicted,
            observed,
            marker="o",
            label=name,
        )

    ax.set_xlabel(
        "Mean predicted attack probability"
    )

    ax.set_ylabel(
        "Observed attack frequency"
    )

    ax.set_title(
        "Attack Probability Calibration - Development"
    )

    ax.legend()

    ax.grid(alpha=0.2)

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "calibration_curve.png",
        dpi=300,
    )

    plt.close(fig)

    # Preserve the original multiclass classifier.

    predictions = model.classes_[
        probabilities.argmax(axis=1)
    ]

    output = pd.DataFrame({

        "ActualLabel": y_multiclass,

        "PredictedLabel": predictions,

        "ActualAttack": y_binary,

        "RawAttackProbability":
            raw_attack_probability,

        "CalibratedAttackProbability":
            calibrated_attack_probability,

        "PredictionConfidence":
            probabilities.max(axis=1),

    })

    output.to_csv(
        RESULTS_DIR
        / "calibrated_validation_predictions.csv",
        index=False,
    )

    # Save calibration parameters in a portable format.

    calibration_parameters = {

        "method": "sigmoid_on_logit",

        "coefficient": float(
            calibrator.coef_[0, 0]
        ),

        "intercept": float(
            calibrator.intercept_[0]
        ),

        "epsilon": EPSILON,

        "target": "attack_vs_benign",

        "fitted_on": "validation",

        "independent_evaluation": False,
    }

    with open(
        RESULTS_DIR / "calibration_parameters.json",
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            calibration_parameters,
            file,
            indent=4,
        )

    # Keep the existing model bundle metadata.

    new_bundle = dict(bundle)

    new_bundle.update({

        "model": model,

        "feature_names": features,

        "labels": labels,

        "model_version":
            "multiclass_rf_v3_calibrated",

        "calibrated": True,

        "calibration":
            calibration_parameters,

        "calibration_scope":
            "binary_attack_probability",

    })

    joblib.dump(
        new_bundle,
        OUTPUT_MODEL,
        compress=3,
    )

    print("\nCalibration parameters:")

    print(
        json.dumps(
            calibration_parameters,
            indent=4,
        )
    )

    print("\n" + "=" * 70)
    print("CALIBRATION COMPLETED")
    print("=" * 70)

    print("Model saved:", OUTPUT_MODEL)

    print(
        "Model size:",
        f"{OUTPUT_MODEL.stat().st_size / 1024**2:.2f} MB",
    )

    print("Results saved:", RESULTS_DIR)

    print(
        "\nOriginal multiclass predictions "
        "remain unchanged."
    )

    print(
        "The final test dataset remains unevaluated."
    )


if __name__ == "__main__":
    main()