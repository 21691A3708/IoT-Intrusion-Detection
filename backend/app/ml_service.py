
from pathlib import Path

import joblib
import pandas as pd


# Resolve the model path from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "models" / "random_forest_capture_based.joblib"

# Features must match the saved model's expected schema and order.
EXPECTED_FEATURES = [
    "Header_Length",
    "Protocol Type",
    "Time_To_Live",
    "Rate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IGMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Variance",
]


def load_saved_model():
    """Load the saved model and verify its feature schema."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            "The trained Random Forest model file was not found."
        )

    saved = joblib.load(MODEL_PATH)

    if not isinstance(saved, dict) or "model" not in saved:
        raise ValueError("Unexpected saved-model format.")

    model = saved["model"]
    feature_names = saved.get("feature_names")

    if feature_names != EXPECTED_FEATURES:
        raise ValueError(
            "The saved model's feature names do not match the expected schema."
        )

    if getattr(model, "n_features_in_", None) != len(EXPECTED_FEATURES):
        raise ValueError("The saved model's feature count is incorrect.")

    return model, saved.get("labels", {})


MODEL, MODEL_LABELS = load_saved_model()


def predict_traffic(features: dict) -> dict:
    """Predict whether one IoT traffic record is normal or an attack."""
    if not isinstance(features, dict):
        raise ValueError("Features must be supplied as an object.")

    missing = [name for name in EXPECTED_FEATURES if name not in features]
    extra = [name for name in features if name not in EXPECTED_FEATURES]

    if missing:
        raise ValueError(f"Missing required features: {missing}")

    if extra:
        raise ValueError(f"Unexpected features: {extra}")

    # Enforce the saved model's feature order.
    ordered_values = []
    for name in EXPECTED_FEATURES:
        value = features[name]

        if isinstance(value, bool):
            raise ValueError(f"Feature '{name}' must be numeric, not boolean.")

        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"Feature '{name}' must be numeric.") from None

        if not pd.notna(number) or number in (float("inf"), float("-inf")):
            raise ValueError(f"Feature '{name}' must be finite.")

        ordered_values.append(number)

    frame = pd.DataFrame([ordered_values], columns=EXPECTED_FEATURES)

    prediction = int(MODEL.predict(frame)[0])
    probabilities = MODEL.predict_proba(frame)[0]

    class_positions = {
        int(class_label): index
        for index, class_label in enumerate(MODEL.classes_)
    }

    if 1 not in class_positions:
        raise ValueError("The saved model does not contain the attack class.")

    attack_probability = float(probabilities[class_positions[1]])

    # Risk thresholds use attack probability, not just the predicted label.
    if attack_probability < 0.25:
        risk_level = "low"
    elif attack_probability < 0.50:
        risk_level = "medium"
    elif attack_probability < 0.75:
        risk_level = "high"
    else:
        risk_level = "critical"

    return {
        "predicted_label": prediction,
        "prediction": "attack" if prediction == 1 else "normal",
        "attack_probability": attack_probability,
        "risk_level": risk_level,
    }

def predict_batch(features_df: pd.DataFrame) -> list[dict]:
    """
    Predict multiple IoT traffic records using the existing model.
    The DataFrame must contain exactly the 36 expected features.
    """

    if not isinstance(features_df, pd.DataFrame):
        raise ValueError("Batch input must be a pandas DataFrame.")

    missing = [
        name for name in EXPECTED_FEATURES
        if name not in features_df.columns
    ]

    extra = [
        name for name in features_df.columns
        if name not in EXPECTED_FEATURES
    ]

    if missing:
        raise ValueError(f"Missing required features: {missing}")

    if extra:
        raise ValueError(f"Unexpected features: {extra}")

    # Preserve the exact feature order expected by the model.
    frame = features_df[EXPECTED_FEATURES].copy()

    # Reject invalid or non-finite values.
    for column in EXPECTED_FEATURES:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")

    if frame.isna().any().any():
        raise ValueError("Batch contains missing or non-numeric feature values.")

    if not frame.map(lambda value: pd.notna(value) and value not in (float("inf"), float("-inf"))).all().all():
        raise ValueError("Batch contains non-finite feature values.")

    predictions = MODEL.predict(frame)
    probabilities = MODEL.predict_proba(frame)

    class_positions = {
        int(class_label): index
        for index, class_label in enumerate(MODEL.classes_)
    }

    if 1 not in class_positions:
        raise ValueError("The saved model does not contain the attack class.")

    attack_probabilities = probabilities[:, class_positions[1]]

    results = []

    for prediction, probability in zip(predictions, attack_probabilities):
        probability = float(probability)

        if probability < 0.25:
            risk_level = "low"
        elif probability < 0.50:
            risk_level = "medium"
        elif probability < 0.75:
            risk_level = "high"
        else:
            risk_level = "critical"

        predicted_label = int(prediction)

        results.append({
            "predicted_label": predicted_label,
            "prediction": "attack" if predicted_label == 1 else "normal",
            "attack_probability": probability,
            "risk_level": risk_level,
        })

    return results
