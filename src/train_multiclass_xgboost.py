from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

from xgboost import XGBClassifier

from sklearn.utils.class_weight import compute_sample_weight

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    log_loss,
)

from multiclass_label_mapping import ID_TO_LABEL


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "processed" / "multiclass"
)

VERIFIED_DIR = DATA_DIR / "verified"

MODEL_DIR = PROJECT_ROOT / "models"

RESULTS_DIR = (
    PROJECT_ROOT / "results" / "multiclass" / "xgboost"
)

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

ALL_LABELS = sorted(ID_TO_LABEL)

CLASS_NAMES = [
    ID_TO_LABEL[label]
    for label in ALL_LABELS
]

with open(
    DATA_DIR / "feature_schema.json",
    encoding="utf-8",
) as file:
    FEATURES = json.load(file)


def load_dataset(split):

    path = VERIFIED_DIR / f"{split}.csv"

    if not path.is_file():
        raise FileNotFoundError(path)

    print(f"\nLoading {split} dataset...")

    df = pd.read_csv(
        path,
        usecols=FEATURES + ["Label"],
        dtype={
            feature: "float32"
            for feature in FEATURES
        },
    )

    X = df[FEATURES]

    y = df["Label"].astype(int)

    if not np.isfinite(X.to_numpy()).all():
        raise ValueError(
            f"Invalid features in {split}"
        )

    print("Rows:", f"{len(X):,}")
    print("Features:", len(FEATURES))

    print("\nClass distribution:")
    print(y.value_counts().sort_index())

    return X, y


def main():

    print("=" * 70)
    print("MULTICLASS XGBOOST TRAINING")
    print("=" * 70)

    X_train, y_train = load_dataset("train")

    X_validation, y_validation = load_dataset(
        "validation"
    )

    if set(y_train.unique()) != set(ALL_LABELS):
        raise ValueError(
            "Training dataset must contain all 8 classes."
        )

    supported_labels = sorted(
        y_validation.unique().tolist()
    )

    missing_labels = sorted(
        set(ALL_LABELS) - set(supported_labels)
    )

    print("\nValidation-supported classes:")

    print([
        ID_TO_LABEL[label]
        for label in supported_labels
    ])

    print("\nUnsupported validation classes:")

    print([
        ID_TO_LABEL[label]
        for label in missing_labels
    ])

    # Balance the training classes.
    sample_weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train,
    ).astype("float32")

    model = XGBClassifier(
        objective="multi:softprob",
        num_class=len(ALL_LABELS),
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        eval_metric="mlogloss",
        early_stopping_rounds=25,
        random_state=RANDOM_STATE,
        n_jobs=4,
    )

    print("\nTraining XGBoost...")

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train,
        sample_weight=sample_weights,
        eval_set=[
            (X_validation, y_validation)
        ],
        verbose=25,
    )

    training_seconds = (
        time.perf_counter() - start
    )

    print(
        f"\nTraining completed in "
        f"{training_seconds:.2f} seconds."
    )

    print(
        "Best iteration:",
        model.best_iteration
    )

    print("\nEvaluating validation dataset...")

    start = time.perf_counter()

    predictions = model.predict(
        X_validation
    ).astype(int)

    prediction_seconds = (
        time.perf_counter() - start
    )

    probabilities = model.predict_proba(
        X_validation
    )

    class_positions = {
        int(label): index
        for index, label in enumerate(model.classes_)
    }

    attack_probability = (
        1.0 - probabilities[:, class_positions[0]]
    )

    metrics = {
        "Model": "XGBoost_Multiclass",

        "EvaluationSplit": "validation",

        "TrainingRows": len(X_train),

        "ValidationRows": len(X_validation),

        "FeatureCount": len(FEATURES),

        "ModelClasses": len(model.classes_),

        "EvaluatedClasses": len(supported_labels),

        "Accuracy": accuracy_score(
            y_validation, predictions
        ),

        "BalancedAccuracy": balanced_accuracy_score(
            y_validation, predictions
        ),

        "MacroPrecision": precision_score(
            y_validation,
            predictions,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        ),

        "MacroRecall": recall_score(
            y_validation,
            predictions,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        ),

        "MacroF1": f1_score(
            y_validation,
            predictions,
            labels=supported_labels,
            average="macro",
            zero_division=0,
        ),

        "WeightedF1": f1_score(
            y_validation,
            predictions,
            average="weighted",
            zero_division=0,
        ),

        "LogLoss": log_loss(
            y_validation,
            probabilities,
            labels=model.classes_,
        ),

        "TrainingSeconds": training_seconds,

        "PredictionSeconds": prediction_seconds,

        "BestIteration": model.best_iteration,
    }

    benign_mask = y_validation.to_numpy() == 0

    if benign_mask.any():

        false_positives = np.sum(
            benign_mask & (predictions != 0)
        )

        metrics["AttackFalsePositiveRate"] = (
            false_positives / benign_mask.sum()
        )

    print("\n" + "=" * 70)
    print("XGBOOST VALIDATION RESULTS")
    print("=" * 70)

    for key, value in metrics.items():

        if isinstance(value, (float, np.floating)):
            print(f"{key}: {value:.6f}")

        else:
            print(f"{key}: {value}")

    report = classification_report(
        y_validation,
        predictions,
        labels=ALL_LABELS,
        target_names=CLASS_NAMES,
        digits=4,
        zero_division=0,
    )

    print("\nClassification report:")
    print(report)

    print(
        "NOTE: BruteForce has no independent "
        "validation support."
    )

    with open(
        RESULTS_DIR / "classification_report.txt",
        "w",
        encoding="utf-8",
    ) as file:
        file.write(report)

    report_dict = classification_report(
        y_validation,
        predictions,
        labels=ALL_LABELS,
        target_names=CLASS_NAMES,
        output_dict=True,
        zero_division=0,
    )

    pd.DataFrame(report_dict).transpose().to_csv(
        RESULTS_DIR / "classification_report.csv"
    )

    pd.DataFrame([metrics]).to_csv(
        RESULTS_DIR / "metrics.csv",
        index=False,
    )

    # Confusion matrix.
    cm = confusion_matrix(
        y_validation,
        predictions,
        labels=ALL_LABELS,
    )

    pd.DataFrame(
        cm,
        index=CLASS_NAMES,
        columns=CLASS_NAMES,
    ).to_csv(
        RESULTS_DIR / "confusion_matrix.csv"
    )

    fig, ax = plt.subplots(
        figsize=(11, 9)
    )

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=CLASS_NAMES,
    )

    display.plot(
        ax=ax,
        cmap="Blues",
        xticks_rotation=45,
        values_format="d",
        colorbar=False,
    )

    ax.set_title(
        "Multiclass XGBoost - Validation"
    )

    plt.tight_layout()

    plt.savefig(
        RESULTS_DIR / "confusion_matrix.png",
        dpi=300,
        bbox_inches="tight",
    )

    plt.close(fig)

    # Save individual predictions.
    prediction_df = pd.DataFrame({

        "ActualLabel": y_validation.to_numpy(),

        "PredictedLabel": predictions,

        "AttackProbability": attack_probability,

        "PredictionConfidence": probabilities.max(
            axis=1
        ),
    })

    prediction_df["ActualFamily"] = (
        prediction_df["ActualLabel"].map(ID_TO_LABEL)
    )

    prediction_df["PredictedFamily"] = (
        prediction_df["PredictedLabel"].map(ID_TO_LABEL)
    )

    for label in ALL_LABELS:

        prediction_df[
            f"Probability_{ID_TO_LABEL[label]}"
        ] = probabilities[:, class_positions[label]]

    prediction_df.to_csv(
        RESULTS_DIR / "validation_predictions.csv",
        index=False,
    )

    # Feature importance.
    importance_df = pd.DataFrame({
        "Feature": FEATURES,
        "Importance": model.feature_importances_,
    }).sort_values(
        "Importance",
        ascending=False,
    )

    importance_df.to_csv(
        RESULTS_DIR / "feature_importance.csv",
        index=False,
    )

    print("\nTop 10 important features:")

    print(
        importance_df.head(10).to_string(
            index=False
        )
    )

    # Save training history.
    history = model.evals_result()

    pd.DataFrame(
        history["validation_0"]
    ).to_csv(
        RESULTS_DIR / "training_history.csv",
        index_label="Iteration",
    )

    # Save model bundle for backend integration.
    model_path = (
        MODEL_DIR / "xgboost_multiclass.joblib"
    )

    joblib.dump(
        {
            "model": model,
            "feature_names": FEATURES,
            "labels": ID_TO_LABEL,
            "model_version": "multiclass_xgb_v1",
            "calibrated": False,
            "validation_supported_labels": supported_labels,
            "random_state": RANDOM_STATE,
        },
        model_path,
        compress=3,
    )

    # Also save the native XGBoost model.
    model.save_model(
        str(MODEL_DIR / "xgboost_multiclass.json")
    )

    print("\n" + "=" * 70)
    print("XGBOOST TRAINING COMPLETED")
    print("=" * 70)

    print("Model saved:", model_path)

    print(
        "Model size:",
        f"{model_path.stat().st_size / (1024 ** 2):.2f} MB"
    )

    print("Results saved:", RESULTS_DIR)

    print(
        "\nThe final test dataset remains reserved "
        "for final model evaluation."
    )


if __name__ == "__main__":
    main()