
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap

MODEL_FILE = Path("models/random_forest_capture_based.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")
OUTPUT_DIR = Path("results/incident_response")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_SIZE = 20
BACKGROUND_SIZE = 100

def risk_level(score):
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"

def recommended_action(prediction, risk):
    if prediction == 0:
        return "LOG_ONLY"
    return {
        "LOW": "MONITOR_AND_LOG",
        "MEDIUM": "RAISE_ALERT_AND_MONITOR",
        "HIGH": "PRIORITIZE_ANALYST_REVIEW",
        "CRITICAL": "URGENT_ANALYST_REVIEW_AND_CONTAINMENT_ASSESSMENT",
    }[risk]

print("Loading capture-separated model...")
saved = joblib.load(MODEL_FILE)
model = saved["model"]
features = saved["feature_names"]

print("Loading test data...")
df = pd.read_csv(TEST_FILE)
X_all = df.reindex(columns=features)

# Select records predicted as attacks, up to SAMPLE_SIZE.
probabilities_all = model.predict_proba(X_all)[:, 1]
attack_indices = np.flatnonzero(probabilities_all >= 0.5)

if len(attack_indices) == 0:
    raise RuntimeError("No predicted attacks found in the test data.")

chosen = attack_indices[:SAMPLE_SIZE]
X_sample = X_all.iloc[chosen].copy()
probabilities = probabilities_all[chosen]
predictions = model.predict(X_sample)

background = X_all.sample(
    n=min(BACKGROUND_SIZE, len(X_all)),
    random_state=42,
)

print(f"Records to explain: {len(X_sample)}")
print("Creating SHAP explainer...")

explainer = shap.TreeExplainer(
    model,
    data=background,
    feature_perturbation="interventional",
    model_output="raw",
)

print("Calculating SHAP values...")
values = explainer.shap_values(
    X_sample,
    check_additivity=False,
)

# Extract SHAP contributions for class 1 (UDP Flood).
if isinstance(values, list):
    attack_values = values[1]
elif getattr(values, "ndim", 0) == 3:
    if values.shape[2] == 2:
        attack_values = values[:, :, 1]
    elif values.shape[1] == 2:
        attack_values = values[:, 1, :]
    else:
        raise ValueError(f"Unexpected SHAP shape: {values.shape}")
else:
    attack_values = values

if attack_values.shape != X_sample.shape:
    raise ValueError(
        f"Unexpected SHAP shape {attack_values.shape}; "
        f"expected {X_sample.shape}"
    )

incidents = []

for position, source_index in enumerate(chosen):
    probability = float(probabilities[position])
    prediction = int(predictions[position])
    score = round(probability * 100, 2)
    risk = risk_level(score)

    contributions = attack_values[position]

    top_positive_indices = np.argsort(contributions)[-3:][::-1]
    top_negative_indices = np.argsort(contributions)[:3]

    positive_text = "; ".join(
        f"{features[i]} ({contributions[i]:+.5f})"
        for i in top_positive_indices
        if contributions[i] > 0
    )

    negative_text = "; ".join(
        f"{features[i]} ({contributions[i]:+.5f})"
        for i in top_negative_indices
        if contributions[i] < 0
    )

    incidents.append({
        "RecordIndex": int(source_index),
        "PredictedClass": (
            "UDP_FLOOD" if prediction == 1 else "NORMAL"
        ),
        "AttackProbability": round(probability, 6),
        "RiskScore": score,
        "RiskLevel": risk,
        "RecommendedAction": recommended_action(prediction, risk),
        "TopPositiveSHAP": positive_text,
        "TopNegativeSHAP": negative_text,
        "ResponseMode": "LAB_ONLY_NOT_EXECUTED",
    })

report = pd.DataFrame(incidents)
output_file = OUTPUT_DIR / "integrated_incident_report.csv"
report.to_csv(output_file, index=False)

print("\nIntegrated incident report:")
print(report.head(10).to_string(index=False))
print(f"\nSaved report: {output_file}")
print("No containment actions were executed.")
