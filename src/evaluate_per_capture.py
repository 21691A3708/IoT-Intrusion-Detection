
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

INPUT_FILE = Path(
    "results/capture_evaluation/heldout_predictions.csv"
)
OUTPUT_FILE = Path(
    "results/capture_evaluation/per_capture_metrics.csv"
)

df = pd.read_csv(INPUT_FILE)
results = []

for capture, group in df.groupby("SourceCapture"):
    actual = group["Actual"].astype(int)
    predicted = group["Predicted"].astype(int)

    tn, fp, fn, tp = confusion_matrix(
        actual, predicted, labels=[0, 1]
    ).ravel()

    results.append({
        "Capture": capture,
        "ActualClass": int(actual.iloc[0]),
        "Records": len(group),
        "Accuracy": accuracy_score(actual, predicted),
        "Precision": precision_score(
            actual, predicted, zero_division=0
        ),
        "Recall": recall_score(
            actual, predicted, zero_division=0
        ),
        "F1": f1_score(
            actual, predicted, zero_division=0
        ),
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
    })

result_df = pd.DataFrame(results)
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
result_df.to_csv(OUTPUT_FILE, index=False)

print("\nPER-CAPTURE EVALUATION")
print("=" * 90)
print(result_df.to_string(index=False, float_format=lambda x: f"{x:.6f}"))

print(f"\nSaved report: {OUTPUT_FILE}")
