
from pathlib import Path
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

TRAIN_FILE = Path("data/processed/splits/train.csv")
TEST_FILE = Path("data/processed/splits/test.csv")
MODEL_DIR = Path("models")
RESULTS_DIR = Path("results")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

print("Loading training and testing data...")
train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)

X_train = train_df.drop(columns=["Label"])
y_train = train_df["Label"].astype(int)

X_test = test_df.drop(columns=["Label"])
y_test = test_df["Label"].astype(int)

# Ensure identical features and order in both datasets.
if list(X_train.columns) != list(X_test.columns):
    raise ValueError("Training and test feature columns do not match.")

# Ensure all features are numeric and finite.
for name, X in [("Training", X_train), ("Testing", X_test)]:
    if not all(pd.api.types.is_numeric_dtype(X[c]) for c in X.columns):
        raise ValueError(f"{name} data contains non-numeric features.")

    if not np.isfinite(X.to_numpy(dtype=np.float64)).all():
        raise ValueError(f"{name} data contains missing or infinite values.")

print("Training records:", f"{len(X_train):,}")
print("Testing records:", f"{len(X_test):,}")
print("Number of features:", X_train.shape[1])

# Establish a reproducible baseline.
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)

print("\nTraining Random Forest...")
start_time = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start_time

print(f"Training time: {training_seconds:.2f} seconds")

# Evaluate once on the held-out test set.
print("\nEvaluating test data...")
prediction_start = time.perf_counter()
y_pred = model.predict(X_test)
prediction_seconds = time.perf_counter() - prediction_start

y_probability = model.predict_proba(X_test)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
roc_auc = roc_auc_score(y_test, y_probability)

# Binary confusion matrix: [[TN, FP], [FN, TP]]
tn, fp, fn, tp = confusion_matrix(
    y_test, y_pred, labels=[0, 1]
).ravel()

fpr = fp / (fp + tn) if (fp + tn) else 0.0

print("\n" + "=" * 55)
print("RANDOM FOREST BASELINE RESULTS")
print("=" * 55)
print(f"Accuracy:          {accuracy:.4f}")
print(f"Precision:         {precision:.4f}")
print(f"Recall:            {recall:.4f}")
print(f"F1-score:          {f1:.4f}")
print(f"ROC-AUC:           {roc_auc:.4f}")
print(f"False-positive rate: {fpr:.4f}")
print(f"Training time:     {training_seconds:.2f} seconds")
print(f"Test prediction time: {prediction_seconds:.2f} seconds")

print("\nConfusion matrix [[TN, FP], [FN, TP]]:")
print(confusion_matrix(y_test, y_pred, labels=[0, 1]))

print("\nClassification report:")
print(classification_report(
    y_test,
    y_pred,
    labels=[0, 1],
    target_names=["Normal", "UDP_Flood"],
    digits=4,
    zero_division=0,
))

# Save the model and its feature names.
model_path = MODEL_DIR / "random_forest.joblib"
joblib.dump(
    {
        "model": model,
        "feature_names": list(X_train.columns),
        "labels": {0: "Normal", 1: "UDP_Flood"},
    },
    model_path,
)

# Save test predictions for later analysis.
predictions_path = RESULTS_DIR / "random_forest_test_predictions.csv"

pd.DataFrame({
    "Actual": y_test.to_numpy(),
    "Predicted": y_pred,
    "AttackProbability": y_probability,
}).to_csv(predictions_path, index=False)

# Save a machine-readable metrics summary.
metrics = pd.DataFrame([{
    "Model": "Random Forest",
    "Accuracy": accuracy,
    "Precision": precision,
    "Recall": recall,
    "F1": f1,
    "ROC_AUC": roc_auc,
    "FPR": fpr,
    "TrainingSeconds": training_seconds,
    "PredictionSeconds": prediction_seconds,
    "TN": int(tn),
    "FP": int(fp),
    "FN": int(fn),
    "TP": int(tp),
}])

metrics.to_csv(RESULTS_DIR / "baseline_metrics.csv", index=False)

print("\nSaved model:", model_path)
print("Saved predictions:", predictions_path)
print("Saved metrics:", RESULTS_DIR / "baseline_metrics.csv")
print("\nBaseline training completed.")
