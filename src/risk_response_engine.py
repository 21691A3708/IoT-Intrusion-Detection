
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

MODEL_FILE = Path("models/random_forest_capture_based.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")
OUTPUT_DIR = Path("results/incident_response")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Initial demonstration thresholds.
# These are configurable policy thresholds, not validated security standards.
LOW_MAX = 24
MEDIUM_MAX = 49
HIGH_MAX = 74

def assign_risk(score):
    if score <= LOW_MAX:
        return "LOW"
    if score <= MEDIUM_MAX:
        return "MEDIUM"
    if score <= HIGH_MAX:
        return "HIGH"
    return "CRITICAL"

def recommend_response(risk, predicted_label):
    if predicted_label == 0:
        return "LOG_ONLY"

    recommendations = {
        "LOW": "MONITOR_AND_LOG",
        "MEDIUM": "RAISE_ALERT_AND_MONITOR",
        "HIGH": "PRIORITIZE_ANALYST_REVIEW",
        "CRITICAL": "URGENT_ANALYST_REVIEW_AND_CONTAINMENT_ASSESSMENT",
    }
    return recommendations[risk]

print("Loading capture-separated model...")
saved = joblib.load(MODEL_FILE)
model = saved["model"]
feature_names = saved["feature_names"]

print("Loading sample records...")
test_df = pd.read_csv(TEST_FILE)

# The original test split has the features expected by the earlier model,
# but Number was excluded from the capture-separated model.
X = test_df.drop(columns=["Label"], errors="ignore")
X = X.reindex(columns=feature_names)

# Use a bounded sample for this initial demonstration.
sample = X.sample(
    n=min(1000, len(X)),
    random_state=42,
).copy()

if not np.isfinite(sample.to_numpy(dtype=float)).all():
    raise ValueError(
        "Non-finite values found. Clean the sample before prediction."
    )

print(f"Records to analyze: {len(sample)}")
print("Predicting attack probabilities...")

probabilities = model.predict_proba(sample)[:, 1]
predictions = model.predict(sample)

incidents = []

for index, (_, row) in enumerate(sample.iterrows()):
    probability = float(probabilities[index])
    predicted_label = int(predictions[index])

    # Risk score for this prototype: model attack probability * 100.
    score = round(probability * 100, 2)
    risk = assign_risk(score)

    # Rank the most influential features using Random Forest importance
    # multiplied by this record's normalized feature magnitude.
    # This is a heuristic, not a SHAP explanation.
    feature_values = row.to_numpy(dtype=float)
    importances = model.feature_importances_
    weighted_values = np.abs(feature_values) * importances

    top_indices = np.argsort(weighted_values)[-3:][::-1]
    top_features = ", ".join(
        feature_names[i] for i in top_indices
    )

    label = "UDP_FLOOD" if predicted_label == 1 else "NORMAL"

    incidents.append({
        "RecordIndex": int(row.name),
        "PredictedClass": label,
        "AttackProbability": round(probability, 6),
        "RiskScore": score,
        "RiskLevel": risk,
        "RecommendedAction": recommend_response(
            risk, predicted_label
        ),
        "TopHeuristicFeatures": top_features,
        "ResponseMode": "SIMULATION_ONLY",
    })

incident_df = pd.DataFrame(incidents)

output_file = OUTPUT_DIR / "incident_report.csv"
incident_df.to_csv(output_file, index=False)

print("\nRISK SUMMARY")
print("=" * 45)
print(incident_df["RiskLevel"].value_counts().to_string())

print("\nPREDICTION SUMMARY")
print(incident_df["PredictedClass"].value_counts().to_string())

print("\nSample incidents:")
print(incident_df.head(10).to_string(index=False))

print(f"\nIncident report saved to: {output_file}")
print("Simulation completed. No network actions were performed.")
