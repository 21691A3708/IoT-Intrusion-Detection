import time
from functools import lru_cache
from threading import Lock

import numpy as np
import shap

from .multiclass_ml_service import (
    MODEL,
    FEATURE_NAMES,
    LABELS,
    MODEL_VERSION,
    CLASS_POSITIONS,
    validate_features,
    format_prediction,
)


ADDITIVITY_TOLERANCE = 1e-5

EXPLAINER_LOCK = Lock()


# --------------------------------------------------
# SHAP EXPLAINER
# --------------------------------------------------

@lru_cache(maxsize=1)
def get_explainer():

    return shap.TreeExplainer(
        MODEL,
        feature_perturbation="tree_path_dependent",
        model_output="raw",
    )


# --------------------------------------------------
# FORMAT SHAP CONTRIBUTIONS
# --------------------------------------------------

def build_explanation(
    feature_values,
    contributions,
    base_value,
    target_probability,
    explained_target,
    top_n,
):

    contributions = np.asarray(
        contributions,
        dtype=float,
    )

    base_value = float(base_value)

    target_probability = float(
        target_probability
    )

    if contributions.shape != (
        len(FEATURE_NAMES),
    ):

        raise RuntimeError(
            "Unexpected contribution dimensions."
        )

    if not np.isfinite(contributions).all():

        raise RuntimeError(
            "Non-finite SHAP contributions."
        )

    if not np.isfinite(
        [base_value, target_probability]
    ).all():

        raise RuntimeError(
            "Non-finite explanation output."
        )

    shap_sum = float(
        contributions.sum()
    )

    reconstructed_probability = (
        base_value + shap_sum
    )

    additivity_error = abs(
        reconstructed_probability
        - target_probability
    )

    ranked_indices = np.argsort(
        np.abs(contributions)
    )[::-1]

    all_features = []

    for index in ranked_indices:

        value = float(
            contributions[index]
        )

        if value > 0:

            impact = "increases_probability"

        elif value < 0:

            impact = "decreases_probability"

        else:

            impact = "neutral"

        all_features.append({

            "feature":
                FEATURE_NAMES[index],

            "feature_value":
                float(feature_values[index]),

            "shap_value":
                value,

            "absolute_importance":
                abs(value),

            "impact":
                impact,
        })

    top_features = all_features[:top_n]

    displayed_sum = sum(
        item["shap_value"]
        for item in top_features
    )

    return {

        "explained_target":
            explained_target,

        "output_space":
            "uncalibrated_probability",

        "base_value":
            base_value,

        "target_probability":
            target_probability,

        "shap_values_sum":
            shap_sum,

        "reconstructed_probability":
            reconstructed_probability,

        "additivity_error":
            additivity_error,

        "additivity_passed": (
            additivity_error
            <= ADDITIVITY_TOLERANCE
        ),

        "feature_count":
            len(FEATURE_NAMES),

        "top_features":
            top_features,

        "remaining_features_sum":
            float(shap_sum - displayed_sum),

        "all_features":
            all_features,
    }


# --------------------------------------------------
# MULTICLASS EXPLANATION
# --------------------------------------------------

def explain_prediction(
    features: dict,
    top_n: int = 10,
    target_class: int | None = None,
) -> dict:

    start_time = time.perf_counter()

    if (
        isinstance(top_n, bool)
        or not isinstance(top_n, int)
        or not 1 <= top_n <= len(FEATURE_NAMES)
    ):

        raise ValueError(
            f"top_n must be between 1 "
            f"and {len(FEATURE_NAMES)}."
        )

    if target_class is not None:

        if (
            isinstance(target_class, bool)
            or not isinstance(target_class, int)
            or target_class not in LABELS
        ):

            raise ValueError(
                "Invalid target class."
            )

    # Reuse the existing strict input validation.

    frame = validate_features(
        features
    )

    probabilities = MODEL.predict_proba(
        frame
    )[0]

    prediction = format_prediction(
        probabilities
    )

    # Default: explain the predicted family.

    explained_label = (
        prediction["predicted_label"]
        if target_class is None
        else target_class
    )

    class_index = CLASS_POSITIONS[
        explained_label
    ]

    benign_index = CLASS_POSITIONS[0]

    # Initialize and access the shared explainer
    # under a lock.

    shap_start = time.perf_counter()

    with EXPLAINER_LOCK:

        explainer = get_explainer()

        explanation = explainer(
            frame,
            check_additivity=True,
        )

    shap_seconds = (
        time.perf_counter() - shap_start
    )

    shap_values = np.asarray(
        explanation.values,
        dtype=float,
    )

    base_values = np.asarray(
        explanation.base_values,
        dtype=float,
    )

    expected_shape = (
        1,
        len(FEATURE_NAMES),
        len(MODEL.classes_),
    )

    if shap_values.shape != expected_shape:

        raise RuntimeError(
            f"Unexpected SHAP shape: "
            f"{shap_values.shape}. "
            f"Expected: {expected_shape}."
        )

    if base_values.shape == (
        1, len(MODEL.classes_)
    ):

        class_bases = base_values[0]

    elif base_values.shape == (
        len(MODEL.classes_),
    ):

        class_bases = base_values

    else:

        raise RuntimeError(
            f"Unexpected base value shape: "
            f"{base_values.shape}"
        )

    if not np.isfinite(shap_values).all():

        raise RuntimeError(
            "SHAP returned non-finite values."
        )

    if not np.isfinite(class_bases).all():

        raise RuntimeError(
            "SHAP returned non-finite baselines."
        )

    feature_values = frame.iloc[0].to_numpy()

    # ----------------------------------------------
    # Verify additivity for all eight classes.
    # ----------------------------------------------

    reconstructed_classes = (
        class_bases
        + shap_values[0].sum(axis=0)
    )

    class_errors = np.abs(
        reconstructed_classes
        - probabilities
    )

    max_class_error = float(
        class_errors.max()
    )

    # ----------------------------------------------
    # Selected-family explanation
    # ----------------------------------------------

    family_explanation = build_explanation(

        feature_values=feature_values,

        contributions=shap_values[
            0, :, class_index
        ],

        base_value=class_bases[
            class_index
        ],

        target_probability=probabilities[
            class_index
        ],

        explained_target=LABELS[
            explained_label
        ],

        top_n=top_n,
    )

    # ----------------------------------------------
    # Overall raw attack probability explanation
    # ----------------------------------------------

    attack_explanation = build_explanation(

        feature_values=feature_values,

        contributions=-shap_values[
            0, :, benign_index
        ],

        base_value=(
            1.0 - class_bases[benign_index]
        ),

        target_probability=prediction[
            "raw_attack_probability"
        ],

        explained_target="AnyAttack",

        top_n=top_n,
    )

    all_passed = bool(

        family_explanation[
            "additivity_passed"
        ]

        and attack_explanation[
            "additivity_passed"
        ]

        and max_class_error
        <= ADDITIVITY_TOLERANCE
    )

    if not all_passed:

        raise RuntimeError(
            "SHAP probability reconstruction "
            "failed additivity verification."
        )

    total_seconds = (
        time.perf_counter() - start_time
    )

    return {

        "model_version":
            MODEL_VERSION,

        "explanation_method":
            "SHAP TreeExplainer",

        "prediction":
            prediction,

        "explained_label":
            explained_label,

        "explained_family":
            LABELS[explained_label],

        "family_explanation":
            family_explanation,

        "attack_explanation":
            attack_explanation,

        "calibrated_attack_probability":
            prediction[
                "calibrated_attack_probability"
            ],

        "shap_output_shape":
            list(shap_values.shape),

        "additivity_verification": {

            "passed":
                all_passed,

            "tolerance":
                ADDITIVITY_TOLERANCE,

            "maximum_class_error":
                max_class_error,

            "class_errors": {

                LABELS[int(label)]:
                    float(class_errors[index])

                for index, label
                in enumerate(MODEL.classes_)
            },
        },

        "shap_latency_ms":
            float(shap_seconds * 1000),

        "total_latency_ms":
            float(total_seconds * 1000),

        "explanation_note": (
            "SHAP explains original model "
            "probabilities, not the nonlinear "
            "calibrated attack probability. "
            "Feature contributions are model "
            "attributions, not causal evidence."
        ),
    }