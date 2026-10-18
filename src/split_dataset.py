
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

INPUT_FILE = Path("data/processed/clean_iot_dataset.csv")
OUTPUT_DIR = Path("data/processed/splits")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading cleaned dataset...")
df = pd.read_csv(INPUT_FILE)

if "Label" not in df.columns:
    raise ValueError("Label column is missing.")

if df.isna().any().any():
    raise ValueError("Missing values remain in the cleaned dataset.")

if set(df["Label"].unique()) != {0, 1}:
    raise ValueError("Expected both labels: 0 and 1.")

# Separate features and target.
X = df.drop(columns=["Label"])
y = df["Label"]

# Stratified 80/20 split.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

train_df = X_train.copy()
train_df["Label"] = y_train

test_df = X_test.copy()
test_df["Label"] = y_test

train_path = OUTPUT_DIR / "train.csv"
test_path = OUTPUT_DIR / "test.csv"

train_df.to_csv(train_path, index=False)
test_df.to_csv(test_path, index=False)

print("\nSPLIT SUMMARY")
print("Total records:", f"{len(df):,}")
print("Training records:", f"{len(train_df):,}")
print("Testing records:", f"{len(test_df):,}")
print("Feature count:", X.shape[1])

print("\nTraining class distribution:")
print(train_df["Label"].value_counts().sort_index())

print("\nTesting class distribution:")
print(test_df["Label"].value_counts().sort_index())

print("\nTraining class proportions:")
print(train_df["Label"].value_counts(normalize=True).sort_index().round(4))

print("\nTesting class proportions:")
print(test_df["Label"].value_counts(normalize=True).sort_index().round(4))

print("\nSaved files:")
print(train_path)
print(test_path)
