from pathlib import Path
from numbers import Real
import math

import joblib
import numpy as np
import pandas as pd

from .calibration_service import (
    calibrate_attack_probability,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "random_forest_multiclass_calibrated.joblib"
)

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

EXPECTED_LABELS = {
    0: "Benign",
    1: "DDoS",
    2: "DoS",
    3: "Reconnaissance",
    4: "BruteForce",
    5: "Spoofing",
    6: "Mirai",
    7: "WebBased",
}

HIGH_CONFIDENCE_THRESHOLD = 0.90


# Load the saved model bundle.

if not MODEL_PATH.is_file():
    raise FileNotFoundError(
        f"Multiclass model not found: {MODEL_PATH}"
    )

BUNDLE = joblib.load(MODEL_PATH)

MODEL = BUNDLE["model"]

FEATURE_NAMES = list(
    BUNDLE["feature_names"]
)

LABELS = {
    int(key): value
    for key, value in BUNDLE["labels"].items()
}

MODEL_VERSION = BUNDLE["model_version"]

CALIBRATION = BUNDLE["calibration"]

MODEL.set_params(verbose=0)


# Validate model metadata.

if FEATURE_NAMES != EXPECTED_FEATURES:
    raise RuntimeError(
        "Multiclass feature schema mismatch."
    )

if LABELS != EXPECTED_LABELS:
    raise RuntimeError(
        "Multiclass label mapping mismatch."
    )

if MODEL.n_features_in_ != len(FEATURE_NAMES):
    raise RuntimeError(
        "Model feature count mismatch."
    )

if list(MODEL.feature_names_in_) != FEATURE_NAMES:
    raise RuntimeError(
        "Model feature order mismatch."
    )

if set(MODEL.classes_) != set(LABELS):
    raise RuntimeError(
        "Model class mapping mismatch."
    )

CLASS_POSITIONS = {
    int(label): index
    for index, label in enumerate(MODEL.classes_)
}


def validate_features(features: dict) -> pd.DataFrame:

    if not isinstance(features, dict):
        raise ValueError(
            "Features must be provided as a dictionary."
        )

    missing = [
        name
        for name in FEATURE_NAMES
        if name not in features
    ]

    extra = [
        name
        for name in features
        if name not in FEATURE_NAMES
    ]

    if missing:
        raise ValueError(
            f"Missing features: {missing}"
        )

    if extra:
        raise ValueError(
            f"Unexpected features: {extra}"
        )

    values = []

    for name in FEATURE_NAMES:

        value = features[name]

        if isinstance(value, (bool, np.bool_)):
            raise ValueError(
                f"{name} cannot be a boolean."
            )

        if not isinstance(value, Real):
            raise ValueError(
                f"{name} must be numeric."
            )

        value = float(value)

        if not math.isfinite(value):
            raise ValueError(
                f"{name} must be finite."
            )

        if abs(value) > np.finfo(np.float32).max:
            raise ValueError(
                f"{name} exceeds the float32 range."
            )

        values.append(value)

    return pd.DataFrame(
        [values],
        columns=FEATURE_NAMES,
        dtype="float32",
    )


def get_detection_status(
    attack_probability: float,
) -> str:

    if attack_probability >= HIGH_CONFIDENCE_THRESHOLD:
        return "high_confidence_attack"

    if attack_probability >= 0.75:
        return "elevated_suspicion"

    if attack_probability >= 0.50:
        return "suspicious"

    return "low_probability"


def format_prediction(probabilities) -> dict:

    probabilities = np.asarray(
        probabilities,
        dtype=float,
    )

    predicted_index = int(
        np.argmax(probabilities)
    )

    predicted_label = int(
        MODEL.classes_[predicted_index]
    )

    predicted_family = LABELS[
        predicted_label
    ]

    benign_index = CLASS_POSITIONS[0]

    benign_probability = float(
        probabilities[benign_index]
    )

    raw_attack_probability = float(
        np.clip(
            1.0 - benign_probability,
            0.0,
            1.0,
        )
    )

    calibrated_probability = (
        calibrate_attack_probability(
            raw_attack_probability,
            CALIBRATION,
        )
    )

    class_probabilities = {
        LABELS[int(label)]: float(
            probabilities[index]
        )
        for index, label in enumerate(MODEL.classes_)
    }

    # Most probable attack family,
    # even if Benign is the overall top class.

    attack_labels = [
        label
        for label in LABELS
        if label != 0
    ]

    candidate_label = max(
        attack_labels,
        key=lambda label: probabilities[
            CLASS_POSITIONS[label]
        ],
    )

    candidate_probability = float(
        probabilities[
            CLASS_POSITIONS[candidate_label]
        ]
    )

    candidate_family = (
        LABELS[candidate_label]
        if candidate_probability > 0
        else None
    )

    return {

        "predicted_label": predicted_label,

        "predicted_family": predicted_family,

        # Original classifier decision.
        "prediction": (
            "normal"
            if predicted_label == 0
            else "attack"
        ),

        "prediction_confidence": float(
            probabilities[predicted_index]
        ),

        "candidate_attack_family":
            candidate_family,

        "candidate_attack_probability":
            candidate_probability,

        "benign_probability":
            benign_probability,

        "raw_attack_probability":
            raw_attack_probability,

        "attack_probability":
            calibrated_probability,

        "calibrated_attack_probability":
            calibrated_probability,

        "class_probabilities":
            class_probabilities,

        "class_probabilities_calibrated":
            False,

        "detection_status":
            get_detection_status(
                calibrated_probability
            ),

        "high_confidence_alert": (
            calibrated_probability
            >= HIGH_CONFIDENCE_THRESHOLD
        ),

        "alert_threshold":
            HIGH_CONFIDENCE_THRESHOLD,

        "model_version":
            MODEL_VERSION,

        "calibration_scope":
            "binary_attack_probability",

        "calibration_independently_validated":
            False,
    }


def predict_traffic(features: dict) -> dict:

    frame = validate_features(features)

    probabilities = MODEL.predict_proba(
        frame
    )[0]

    return format_prediction(
        probabilities
    )


def predict_batch(records: list) -> list:

    if not isinstance(records, list):
        raise ValueError(
            "Records must be provided as a list."
        )

    if not records:
        return []

    frames = [
        validate_features(record)
        for record in records
    ]

    frame = pd.concat(
        frames,
        ignore_index=True,
    )

    probabilities = MODEL.predict_proba(
        frame
    )

    return [
        format_prediction(row)
        for row in probabilities
    ]


def get_model_info() -> dict:

    return {

        "model_version":
            MODEL_VERSION,

        "algorithm":
            "RandomForestClassifier",

        "configuration":
            BUNDLE.get("configuration"),

        "feature_count":
            len(FEATURE_NAMES),

        "features":
            FEATURE_NAMES,

        "class_count":
            len(LABELS),

        "labels":
            LABELS,

        "calibrated":
            BUNDLE.get("calibrated", False),

        "calibration_scope":
            BUNDLE.get("calibration_scope"),

        "validation_supported_labels":
            BUNDLE.get(
                "validation_supported_labels",
                [],
            ),

        "high_confidence_threshold":
            HIGH_CONFIDENCE_THRESHOLD,
    }