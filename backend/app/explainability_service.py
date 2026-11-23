
import numpy as np
import pandas as pd
import shap

from .ml_service import MODEL, EXPECTED_FEATURES


# Create the SHAP explainer once and reuse it
EXPLAINER = shap.TreeExplainer(MODEL)

# Find the model output index corresponding to class 1 (attack)
ATTACK_CLASS_INDEX = int(
    np.where(np.asarray(MODEL.classes_) == 1)[0][0]
)


def explain_prediction(features: dict, top_n: int = 10) -> dict:
    """
    Generate SHAP feature contributions for an IoT traffic record.
    Positive values push towards attack; negative values push
    towards normal traffic.
    """

    if not isinstance(features, dict):
        raise ValueError("Features must be provided as a dictionary.")

    missing_features = [
        name for name in EXPECTED_FEATURES if name not in features
    ]

    extra_features = [
        name for name in features if name not in EXPECTED_FEATURES
    ]

    if missing_features:
        raise ValueError(
            f"Missing required features: {missing_features}"
        )

    if extra_features:
        raise ValueError(
            f"Unexpected features: {extra_features}"
        )

    try:
        ordered_values = [
            float(features[name]) for name in EXPECTED_FEATURES
        ]
    except (TypeError, ValueError):
        raise ValueError("All feature values must be numeric.")

    if not np.isfinite(ordered_values).all():
        raise ValueError("Feature values must be finite numbers.")

    if top_n < 1 or top_n > len(EXPECTED_FEATURES):
        raise ValueError(
            f"top_n must be between 1 and {len(EXPECTED_FEATURES)}."
        )

    # Preserve the exact feature order used during model training
    input_df = pd.DataFrame(
        [ordered_values],
        columns=EXPECTED_FEATURES
    )

    # Generate SHAP explanation
    explanation = EXPLAINER(input_df)

    shap_values = np.asarray(explanation.values)

    # Handle SHAP output shapes across versions
    if shap_values.ndim == 3:
        contributions = shap_values[
            0, :, ATTACK_CLASS_INDEX
        ]
    elif shap_values.ndim == 2:
        contributions = shap_values[0, :]
    else:
        raise ValueError(
            f"Unexpected SHAP values shape: {shap_values.shape}"
        )

    base_values = np.asarray(explanation.base_values)

    if base_values.ndim == 2:
        base_value = float(
            base_values[0, ATTACK_CLASS_INDEX]
        )
    elif base_values.ndim == 1:
        if len(base_values) > 1:
            base_value = float(
                base_values[ATTACK_CLASS_INDEX]
            )
        else:
            base_value = float(base_values[0])
    else:
        base_value = float(base_values)

    # Rank features by absolute SHAP contribution
    ranked_indices = np.argsort(
        np.abs(contributions)
    )[::-1][:top_n]

    top_features = []

    for index in ranked_indices:
        shap_value = float(contributions[index])

        top_features.append({
            "feature": EXPECTED_FEATURES[index],
            "feature_value": float(ordered_values[index]),
            "shap_value": shap_value,
            "impact": (
                "toward_attack"
                if shap_value > 0
                else "toward_normal"
                if shap_value < 0
                else "neutral"
            )
        })

    return {
        "base_value": base_value,
        "shap_values_sum": float(np.sum(contributions)),
        "top_features": top_features,
        "explained_class": "attack"
    }
