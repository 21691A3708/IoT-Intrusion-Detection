
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import shap

MODEL_FILE = Path("models/random_forest.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")
OUTPUT_DIR = Path("results/shap")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Keep the initial explanation sample small.
BACKGROUND_SIZE = 100
EXPLANATION_SIZE = 200

print("Loading trained model...")
saved = joblib.load(MODEL_FILE)
model = saved["model"]
feature_names = saved["feature_names"]

print("Loading test data...")
test_df = pd.read_csv(TEST_FILE)

X_test = test_df[feature_names]
y_test = test_df["Label"].astype(int)

# Use a fixed seed so results are reproducible.
background = X_test.sample(
    n=min(BACKGROUND_SIZE, len(X_test)),
    random_state=42
)

sample_indices = X_test.sample(
    n=min(EXPLANATION_SIZE, len(X_test)),
    random_state=123
).index

X_explain = X_test.loc[sample_indices].copy()
y_explain = y_test.loc[sample_indices].copy()

print(f"Background records: {len(background)}")
print(f"Records to explain: {len(X_explain)}")
print("Creating SHAP TreeExplainer...")

explainer = shap.TreeExplainer(
    model,
    data=background,
    feature_perturbation="interventional",
    model_output="raw"
)

print("Calculating SHAP values...")
shap_values = explainer.shap_values(X_explain, check_additivity=False)

# SHAP output dimensions can vary by SHAP version.
# Select class 1 (UDP Flood) for binary classification.
if isinstance(shap_values, list):
    attack_shap = shap_values[1]
elif getattr(shap_values, "ndim", 0) == 3:
    if shap_values.shape[2] == 2:
        attack_shap = shap_values[:, :, 1]
    elif shap_values.shape[1] == 2:
        attack_shap = shap_values[:, 1, :]
    else:
        raise ValueError(
            f"Unexpected SHAP output shape: {shap_values.shape}"
        )
else:
    attack_shap = shap_values

if attack_shap.shape != X_explain.shape:
    raise ValueError(
        f"SHAP shape {attack_shap.shape} does not match "
        f"feature shape {X_explain.shape}"
    )

print("Saving global feature-importance plot...")
shap.summary_plot(
    attack_shap,
    X_explain,
    feature_names=feature_names,
    max_display=15,
    show=False
)
plt.tight_layout()
plt.savefig(
    OUTPUT_DIR / "shap_summary.png",
    dpi=200,
    bbox_inches="tight"
)
plt.close()

print("Saving mean absolute SHAP values...")
importance_df = pd.DataFrame({
    "Feature": feature_names,
    "MeanAbsSHAP": abs(attack_shap).mean(axis=0)
}).sort_values("MeanAbsSHAP", ascending=False)

importance_df.to_csv(
    OUTPUT_DIR / "shap_feature_importance.csv",
    index=False
)

print("\nTop 15 features by mean absolute SHAP value:")
print(importance_df.head(15).to_string(index=False))

print("Saving a local explanation for the first record...")
local_df = pd.DataFrame({
    "Feature": feature_names,
    "FeatureValue": X_explain.iloc[0].to_numpy(),
    "SHAPValue": attack_shap[0]
})
local_df["AbsoluteSHAP"] = local_df["SHAPValue"].abs()
local_df = local_df.sort_values(
    "AbsoluteSHAP", ascending=False
)
local_df.to_csv(
    OUTPUT_DIR / "local_explanation.csv",
    index=False
)

print("\nFirst explained record:")
print(f"Actual label: {y_explain.iloc[0]}")
print(f"Predicted label: {model.predict(X_explain.iloc[[0]])[0]}")
print("\nTop 10 contributions for this record:")
print(local_df.head(10).to_string(index=False))

print("\nSHAP analysis completed.")
print(f"Results saved in: {OUTPUT_DIR}")
