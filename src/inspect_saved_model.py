
from pathlib import Path
import joblib

model_path = (
    Path(__file__).resolve().parent.parent
    / "models"
    / "random_forest_capture_based.joblib"
)

saved = joblib.load(model_path)

print("Saved object type:", type(saved).__name__)

if isinstance(saved, dict):
    print("\nDictionary keys:")
    for key, value in saved.items():
        print(f"\nKey: {key!r}")
        print("Value type:", type(value).__name__)

        if hasattr(value, "n_features_in_"):
            print("Expected feature count:", value.n_features_in_)

        if hasattr(value, "feature_names_in_"):
            print("Feature names:")
            print(list(value.feature_names_in_))

        if hasattr(value, "classes_"):
            print("Classes:", list(value.classes_))
else:
    print("Expected features:", getattr(saved, "n_features_in_", "Unknown"))
    print("Feature names:", getattr(saved, "feature_names_in_", "Not stored"))
