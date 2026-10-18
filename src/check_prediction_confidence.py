
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

MODEL_FILE = Path("models/random_forest_capture_based.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")

saved = joblib.load(MODEL_FILE)
model = saved["model"]
features = saved["feature_names"]

df = pd.read_csv(TEST_FILE)
X = df.reindex(columns=features)

X = X.sample(n=min(1000, len(X)), random_state=42)

probabilities = model.predict_proba(X)[:, 1]

print("PREDICTION CONFIDENCE ANALYSIS")
print("=" * 45)
print("Records:", len(probabilities))
print("Minimum:", round(float(probabilities.min()), 6))
print("Maximum:", round(float(probabilities.max()), 6))
print("Mean:", round(float(probabilities.mean()), 6))
print("Standard deviation:", round(float(probabilities.std()), 6))

print("\nProbability quantiles:")
print(
    pd.Series(probabilities)
    .quantile([0, 0.01, 0.05, 0.25, 0.50, 0.75, 0.95, 0.99, 1])
    .to_string()
)


print("\nProbability distribution:")

bins = [-0.001, 0.01, 0.10, 0.25, 0.50, 0.75, 0.90, 0.99, 1.001]
labels = [
    "0-1%", "1-10%", "10-25%", "25-50%",
    "50-75%", "75-90%", "90-99%", "99-100%"
]

distribution = pd.cut(
    probabilities,
    bins=bins,
    labels=labels,
    include_lowest=True,
    right=True,
)

distribution_series = pd.Series(distribution)
print(distribution_series.value_counts(sort=False).to_string())

print("\nConfidence analysis completed.")
