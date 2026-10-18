
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import StandardScaler

TRAIN_FILE = Path("data/processed/splits/train.csv")
OUTPUT_FILE = Path("results/feature_separation.csv")

print("Loading training data...")
df = pd.read_csv(TRAIN_FILE)

X = df.drop(columns=["Label", "Number"])
y = df["Label"].astype(int)

# Standardize for a consistent numerical diagnostic.
# Standardization is used only for this analysis.
X_scaled = StandardScaler().fit_transform(X)

print("Calculating mutual information...")
mi = mutual_info_classif(
    X_scaled,
    y,
    random_state=42,
    n_neighbors=3,
)

results = pd.DataFrame({
    "Feature": X.columns,
    "MutualInformation": mi,
    "NormalMean": [
        df.loc[y == 0, c].mean() for c in X.columns
    ],
    "AttackMean": [
        df.loc[y == 1, c].mean() for c in X.columns
    ],
})

results["AbsoluteMeanDifference"] = (
    results["AttackMean"] - results["NormalMean"]
).abs()

results = results.sort_values(
    "MutualInformation", ascending=False
)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
results.to_csv(OUTPUT_FILE, index=False)

print("\nTop 15 features by mutual information:")
print(
    results.head(15)[
        ["Feature", "MutualInformation",
         "NormalMean", "AttackMean"]
    ].to_string(index=False)
)

print(f"\nSaved report: {OUTPUT_FILE}")
print("Feature separation analysis completed.")
