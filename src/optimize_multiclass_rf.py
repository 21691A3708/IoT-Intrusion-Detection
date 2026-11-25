from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier

from sklearn.utils.class_weight import (
    compute_class_weight,
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    log_loss,
    classification_report,
)

from multiclass_label_mapping import ID_TO_LABEL


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "processed" / "multiclass"
)

MODEL_DIR = PROJECT_ROOT / "models"

OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "multiclass"
    / "optimization"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

with open(
    DATA_DIR / "feature_schema.json",
    encoding="utf-8",
) as file:
    FEATURES = json.load(file)


def load_data(split):

    df = pd.read_csv(
        DATA_DIR / "verified" / f"{split}.csv",
        usecols=FEATURES + ["Label"],
        dtype={
            feature: "float32"
            for feature in FEATURES
        },
    )

    return (
        df[FEATURES],
        df["Label"].astype(int),
    )


def evaluate(model, X, y):

    probabilities = model.predict_proba(X)

    predictions = model.classes_[
        probabilities.argmax(axis=1)
    ]

    supported_labels = sorted(y.unique())

    benign_mask = y.to_numpy() == 0

    fpr = np.mean(
        predictions[benign_mask] != 0
    )

    return {
        "Accuracy": accuracy_score(
            y, predictions
        ),

        "MacroF1": f1_score(
            y,
            predictions,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        ),

        "BalancedAccuracy": recall_score(
            y,
            predictions,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        ),

        "MacroPrecision": precision_score(
            y,
            predictions,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        ),

        "AttackFalsePositiveRate": fpr,

        "ReconnaissanceRecall": recall_score(
            y == 3,
            predictions == 3,
            zero_division=0,
        ),

        "SpoofingRecall": recall_score(
            y == 5,
            predictions == 5,
            zero_division=0,
        ),

        "LogLoss": log_loss(
            y,
            probabilities,
            labels=model.classes_,
        ),
    }


def main():

    print("=" * 75)
    print("RANDOM FOREST OPTIMIZATION")
    print("=" * 75)

    X_train, y_train = load_data("train")

    X_val, y_val = load_data("validation")

    classes = np.sort(y_train.unique())

    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y_train,
    )

    balanced_weights = {
        int(label): float(weight)
        for label, weight in zip(classes, weights)
    }

    moderate_weights = {
        label: float(np.sqrt(weight))
        for label, weight in balanced_weights.items()
    }

    benign_priority = balanced_weights.copy()

    benign_priority[0] *= 2.0

    configurations = {

        "RF_Deep": {
            "n_estimators": 150,
            "max_depth": 30,
            "min_samples_leaf": 2,
            "class_weight": "balanced",
        },

        "RF_Regularized": {
            "n_estimators": 150,
            "max_depth": 25,
            "min_samples_leaf": 5,
            "class_weight": "balanced",
        },

        "RF_ModerateWeights": {
            "n_estimators": 100,
            "max_depth": 25,
            "min_samples_leaf": 2,
            "class_weight": moderate_weights,
        },

        "RF_BenignPriority": {
            "n_estimators": 100,
            "max_depth": 25,
            "min_samples_leaf": 2,
            "class_weight": benign_priority,
        },
    }

    baseline_bundle = joblib.load(
        MODEL_DIR / "random_forest_multiclass.joblib"
    )

    baseline_model = baseline_bundle["model"]

    if baseline_bundle["feature_names"] != FEATURES:
        raise ValueError("Baseline feature schema mismatch.")

    baseline_model.set_params(verbose=0)

    baseline_metrics = evaluate(
        baseline_model,
        X_val,
        y_val,
    )

    baseline_metrics["Configuration"] = "RF_Baseline"

    records = [baseline_metrics]

    # Primary development selection criterion:
    # macro F1, with lower false-positive rate
    # used as a tie-breaker.
    best_metrics = baseline_metrics.copy()

    best_model = baseline_model

    best_name = "RF_Baseline"

    print("\nBASELINE METRICS")

    for key, value in baseline_metrics.items():
        print(f"{key}: {value}")

    for name, parameters in configurations.items():

        print("\n" + "=" * 75)
        print("TRAINING:", name)
        print("=" * 75)

        model = RandomForestClassifier(
            **parameters,
            max_features="sqrt",
            random_state=RANDOM_STATE,
            n_jobs=4,
            verbose=1,
        )

        start = time.perf_counter()

        model.fit(X_train, y_train)

        elapsed = time.perf_counter() - start

        model.set_params(verbose=0)

        metrics = evaluate(
            model,
            X_val,
            y_val,
        )

        metrics["Configuration"] = name

        metrics["TrainingSeconds"] = elapsed

        records.append(metrics)

        for key, value in metrics.items():

            if isinstance(value, (float, np.floating)):
                print(f"{key}: {value:.6f}")
            else:
                print(f"{key}: {value}")

        candidate_score = (
            metrics["MacroF1"],
            -metrics["AttackFalsePositiveRate"],
        )

        best_score = (
            best_metrics["MacroF1"],
            -best_metrics["AttackFalsePositiveRate"],
        )

        if candidate_score > best_score:

            best_model = model

            best_metrics = metrics.copy()

            best_name = name

        del model

        # Save partial results after each experiment.
        pd.DataFrame(records).to_csv(
            OUTPUT_DIR / "optimization_results.csv",
            index=False,
        )

    results = pd.DataFrame(records)

    results = results.sort_values(
        ["MacroF1", "AttackFalsePositiveRate"],
        ascending=[False, True],
    )

    results.to_csv(
        OUTPUT_DIR / "optimization_results.csv",
        index=False,
    )

    print("\n" + "=" * 75)
    print("OPTIMIZATION RESULTS")
    print("=" * 75)

    print(
        results.round(6).to_string(index=False)
    )

    print("\nBest Macro F1 configuration:", best_name)

    print(
        "Lowest FPR configuration:",
        results.loc[
            results["AttackFalsePositiveRate"].idxmin(),
            "Configuration",
        ],
    )

    predictions = best_model.predict(X_val)

    report = classification_report(
        y_val,
        predictions,
        labels=sorted(ID_TO_LABEL),
        target_names=[
            ID_TO_LABEL[label]
            for label in sorted(ID_TO_LABEL)
        ],
        digits=4,
        zero_division=0,
    )

    print("\nSELECTED MODEL CLASSIFICATION REPORT")
    print(report)

    with open(
        OUTPUT_DIR / "classification_report.txt",
        "w",
        encoding="utf-8",
    ) as file:
        file.write(report)

    model_path = (
        MODEL_DIR
        / "random_forest_multiclass_optimized.joblib"
    )

    joblib.dump(
        {
            "model": best_model,
            "feature_names": FEATURES,
            "labels": ID_TO_LABEL,
            "model_version": "multiclass_rf_v2",
            "configuration": best_name,
            "validation_metrics": best_metrics,
            "calibrated": False,
            "validation_supported_labels": sorted(
                int(label)
                for label in y_val.unique()
            ),
            "random_state": RANDOM_STATE,
        },
        model_path,
        compress=3,
    )

    print("\nSelected model saved:", model_path)

    print(
        "Model size:",
        f"{model_path.stat().st_size / 1024**2:.2f} MB",
    )

    print("\nOptimization completed.")

    print(
        "Final test records remain unevaluated."
    )


if __name__ == "__main__":
    main()