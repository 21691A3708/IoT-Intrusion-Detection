
from pathlib import Path

import pandas as pd
import joblib

MODEL_FILE = Path("models/random_forest.joblib")
OUTPUT_DIR = Path("results")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading trained Random Forest model...")

saved = joblib.load(MODEL_FILE)
model = saved["model"]
feature_names = saved["feature_names"]

importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": model.feature_importances_
})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
).reset_index(drop=True)

importance_df.to_csv(
    OUTPUT_DIR / "random_forest_feature_importance.csv",
    index=False
)

print("\nTop 15 most important features:")
print(importance_df.head(15).to_string(index=False))

print("\nSaved to:")
print(OUTPUT_DIR / "random_forest_feature_importance.csv")

print("\nFeature importance analysis completed.")
