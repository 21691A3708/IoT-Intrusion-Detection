
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

DATA_DIR = Path("data/raw/extracted/CSV")
RESULTS_DIR = Path("results/capture_evaluation")
MODEL_DIR = Path("models")

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_FILES = [
    (DATA_DIR / "Benign_Final" / "BenignTraffic.pcap.csv", 0),
    (DATA_DIR / "Benign_Final" / "BenignTraffic1.pcap.csv", 0),
    (DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood.pcap.csv", 1),
    (DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood1.pcap.csv", 1),
]

TEST_FILES = [
    (DATA_DIR / "Benign_Final" / "BenignTraffic2.pcap.csv", 0),
    (DATA_DIR / "DoS-UDP_Flood" / "DoS-UDP_Flood2.pcap.csv", 1),
]

EXCLUDED_FEATURES = {
    "Number",
    "Telnet",
    "SMTP",
}

def load_capture_files(file_specs, split_name):
    frames = []

    for path, label in file_specs:
        print(f"Loading {split_name}: {path.name}")
        df = pd.read_csv(path)

        # Verify the source file has the expected label-free schema.
        if "Label" in df.columns:
            raise ValueError(
                f"Unexpected Label column in raw capture: {path}"
            )

        df["Label"] = label
        df["SourceCapture"] = path.name
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)

    print(f"{split_name} rows before cleaning: {len(combined):,}")

    # Remove known constant or excluded features.
    combined = combined.drop(
        columns=list(EXCLUDED_FEATURES),
        errors="ignore",
    )

    feature_cols = [
        col for col in combined.columns
        if col not in {"Label", "SourceCapture"}
    ]

    # Convert infinite values to missing values and remove invalid rows.
    combined[feature_cols] = combined[feature_cols].replace(
        [np.inf, -np.inf], np.nan
    )
    combined = combined.dropna(
        subset=feature_cols + ["Label"]
    ).reset_index(drop=True)

    print(f"{split_name} rows after cleaning: {len(combined):,}")
    print("Label counts:")
    print(combined["Label"].value_counts().sort_index().to_string())

    return combined, feature_cols


print("Loading training captures...")
train_df, train_features = load_capture_files(
    TRAIN_FILES, "TRAIN"
)

print("\nLoading held-out test captures...")
test_df, test_features = load_capture_files(
    TEST_FILES, "TEST"
)

if train_features != test_features:
    raise ValueError("Training and test features do not match.")

X_train = train_df[train_features]
y_train = train_df["Label"].astype(int)

X_test = test_df[test_features]
y_test = test_df["Label"].astype(int)

print("\nTraining feature count:", len(train_features))
print("Training rows:", len(X_train))
print("Testing rows:", len(X_test))

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=2,
)

print("\nTraining capture-based Random Forest...")
start = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start

print(f"Training time: {training_seconds:.2f} seconds")

print("\nEvaluating held-out captures...")
start = time.perf_counter()
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]
prediction_seconds = time.perf_counter() - start

tn, fp, fn, tp = confusion_matrix(
    y_test, predictions, labels=[0, 1]
).ravel()

metrics = {
    "Model": "RandomForest_CaptureSeparated",
    "Accuracy": accuracy_score(y_test, predictions),
    "Precision": precision_score(
        y_test, predictions, zero_division=0
    ),
    "Recall": recall_score(
        y_test, predictions, zero_division=0
    ),
    "F1": f1_score(y_test, predictions, zero_division=0),
    "ROC_AUC": roc_auc_score(y_test, probabilities),
    "FalsePositiveRate": fp / (fp + tn) if (fp + tn) else 0,
    "TrainingSeconds": training_seconds,
    "PredictionSeconds": prediction_seconds,
    "TN": tn,
    "FP": fp,
    "FN": fn,
    "TP": tp,
}

print("\n" + "=" * 55)
print("CAPTURE-SEPARATED EVALUATION RESULTS")
print("=" * 55)

for key, value in metrics.items():
    if isinstance(value, (float, np.floating)):
        print(f"{key}: {value:.4f}")
    else:
        print(f"{key}: {value}")

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Normal", "UDP_Flood"],
    digits=4,
    zero_division=0,
))

# Save predictions alongside their source capture for analysis.
prediction_df = pd.DataFrame({
    "SourceCapture": test_df["SourceCapture"],
    "Actual": y_test,
    "Predicted": predictions,
    "AttackProbability": probabilities,
})
prediction_df.to_csv(
    RESULTS_DIR / "heldout_predictions.csv",
    index=False,
)

pd.DataFrame([metrics]).to_csv(
    RESULTS_DIR / "metrics.csv",
    index=False,
)

joblib.dump(
    {
        "model": model,
        "feature_names": train_features,
        "labels": {0: "Normal", 1: "UDP_Flood"},
        "training_captures": [p.name for p, _ in TRAIN_FILES],
        "test_captures": [p.name for p, _ in TEST_FILES],
    },
    MODEL_DIR / "random_forest_capture_based.joblib",
)

print("\nSaved metrics:", RESULTS_DIR / "metrics.csv")
print("Saved predictions:", RESULTS_DIR / "heldout_predictions.csv")
print("Saved model:", MODEL_DIR / "random_forest_capture_based.joblib")
print("Capture-based evaluation completed.")
