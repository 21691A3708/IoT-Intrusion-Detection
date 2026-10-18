
from pathlib import Path

import joblib
import pandas as pd
import shap

MODEL_FILE = Path("models/random_forest_capture_based.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")
OUTPUT_DIR = Path("results/incident_response")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading capture-separated model...")
saved = joblib.load(MODEL_FILE)
model = saved["model"]
features = saved["feature_names"]

print("Loading test records...")
df = pd.read_csv(TEST_FILE)
X = df.reindex(columns=features)

# Select one record that the model predicts as an attack.
probabilities = model.predict_proba(X)[:, 1]
attack_indices = [
    i for i, probability in enumerate(probabilities)
    if probability >= 0.5
]

if not attack_indices:
    raise RuntimeError("No attack predictions found in this test set.")

record_index = attack_indices[0]
record = X.iloc[[record_index]]

print("Selected record index:", record_index)
print("Attack probability:", round(float(probabilities[record_index]), 6))

# A small background sample helps limit memory use.
background = X.sample(
    n=min(100, len(X)),
    random_state=42,
)

print("Creating SHAP explainer...")
explainer = shap.TreeExplainer(
    model,
    data=background,
    feature_perturbation="interventional",
    model_output="raw",
)

print("Calculating SHAP values...")
values = explainer.shap_values(
    record,
    check_additivity=False,
)

# Support SHAP output formats for binary classification.
if isinstance(values, list):
    attack_values = values[1][0]
elif getattr(values, "ndim", 0) == 3:
    if values.shape[2] == 2:
        attack_values = values[0, :, 1]
    elif values.shape[1] == 2:
        attack_values = values[0, 1, :]
    else:
        raise ValueError(f"Unexpected SHAP shape: {values.shape}")
else:
    attack_values = values[0]

if len(attack_values) != len(features):
    raise ValueError("SHAP values do not match the feature count.")

explanation = pd.DataFrame({
    "Feature": features,
    "FeatureValue": record.iloc[0].to_numpy(),
    "SHAPValue": attack_values,
})

explanation["AbsoluteSHAP"] = explanation["SHAPValue"].abs()
explanation = explanation.sort_values(
    "AbsoluteSHAP",
    ascending=False,
)

output_file = OUTPUT_DIR / "shap_incident_explanation.csv"
explanation.to_csv(output_file, index=False)

print("\nTop 10 SHAP contributions:")
print(explanation.head(10).to_string(index=False))

print("\nSaved explanation:", output_file)
print("SHAP incident explanation completed.")
