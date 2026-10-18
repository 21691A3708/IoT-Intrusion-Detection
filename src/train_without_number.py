
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

TRAIN_FILE = Path("data/processed/splits/train.csv")
TEST_FILE = Path("data/processed/splits/test.csv")
MODEL_DIR = Path("models")
RESULTS_DIR = Path("results")

MODEL_DIR.mkdir(exist_ok=True, parents=True)
RESULTS_DIR.mkdir(exist_ok=True, parents=True)

print("Loading train and test data...")
train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)

# Remove the feature that may be acting as a shortcut.
excluded_features = ["Label", "Number"]
features = [c for c in train_df.columns if c not in excluded_features]

X_train = train_df[features]
y_train = train_df["Label"].astype(int)
X_test = test_df[features]
y_test = test_df["Label"].astype(int)

print("Features used:", len(features))
print("Excluded feature: Number")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=2,
)

print("\nTraining Random Forest without Number...")
start = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start

start = time.perf_counter()
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]
prediction_seconds = time.perf_counter() - start

tn, fp, fn, tp = confusion_matrix(
    y_test, predictions, labels=[0, 1]
).ravel()

metrics = {
    "Model": "RandomForest_without_Number",
    "Accuracy": accuracy_score(y_test, predictions),
    "Precision": precision_score(
        y_test, predictions, zero_division=0
    ),
    "Recall": recall_score(
        y_test, predictions, zero_division=0
    ),
    "F1": f1_score(y_test, predictions, zero_division=0),
    "ROC_AUC": roc_auc_score(y_test, probabilities),
    "FalsePositiveRate": fp / (fp + tn) if fp + tn else 0,
    "TrainingSeconds": training_seconds,
    "PredictionSeconds": prediction_seconds,
    "TN": tn,
    "FP": fp,
    "FN": fn,
    "TP": tp,
}

print("\nRESULTS WITHOUT Number")
print("=" * 45)
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

joblib.dump(
    {
        "model": model,
        "feature_names": features,
        "labels": {0: "Normal", 1: "UDP_Flood"},
    },
    MODEL_DIR / "random_forest_without_number.joblib",
)

pd.DataFrame([metrics]).to_csv(
    RESULTS_DIR / "metrics_without_number.csv",
    index=False,
)

print("\nSaved model: models/random_forest_without_number.joblib")
print("Saved metrics: results/metrics_without_number.csv")
print("Experiment completed.")
