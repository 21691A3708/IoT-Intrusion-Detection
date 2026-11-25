import math
from numbers import Real

from .device_context_service import (
    get_device_context,
)

from .attack_impact_service import (
    calculate_attack_impact,
)

from .multiclass_ml_service import (
    predict_traffic,
)


RISK_POLICY_VERSION = "context_risk_v1"

RISK_WEIGHTS = {

    "criticality": 0.40,

    "attack_impact": 0.40,

    "exposure": 0.20,
}


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

def validate_unit_value(
    value,
    name: str,
) -> float:

    if (
        isinstance(value, bool)
        or not isinstance(value, Real)
    ):

        raise ValueError(
            f"{name} must be numeric."
        )

    value = float(value)

    if (
        not math.isfinite(value)
        or not 0 <= value <= 1
    ):

        raise ValueError(
            f"{name} must be between 0 and 1."
        )

    return value


# --------------------------------------------------
# RISK SCORE
# --------------------------------------------------

def calculate_risk_score(

    attack_probability: float,

    criticality: float,

    attack_impact: float,

    exposure: float,

) -> float:

    probability = validate_unit_value(

        attack_probability,

        "attack_probability",
    )

    criticality = validate_unit_value(

        criticality,

        "criticality",
    )

    attack_impact = validate_unit_value(

        attack_impact,

        "attack_impact",
    )

    exposure = validate_unit_value(

        exposure,

        "exposure",
    )

    context_score = (

        RISK_WEIGHTS["criticality"]
        * criticality

        + RISK_WEIGHTS["attack_impact"]
        * attack_impact

        + RISK_WEIGHTS["exposure"]
        * exposure
    )

    risk_score = (

        100 * probability * context_score
    )

    return float(risk_score)


# --------------------------------------------------
# SEVERITY CLASSIFICATION
# --------------------------------------------------

def get_risk_level(
    risk_score: float,
) -> str:

    if risk_score < 25:

        return "low"

    if risk_score < 50:

        return "medium"

    if risk_score < 75:

        return "high"

    return "critical"


# --------------------------------------------------
# NON-DISRUPTIVE RECOMMENDATION
# --------------------------------------------------

def recommend_action(

    risk_level: str,

    detection_status: str,

    context_known: bool,

) -> str:

    if risk_level == "critical":

        return "priority_investigation"

    if risk_level == "high":

        return "alert_and_investigate"

    # High attack confidence must not be ignored
    # simply because the device has low criticality.

    if detection_status == "high_confidence_attack":

        return "alert_and_investigate"

    if detection_status == "elevated_suspicion":

        return "review_suspicious_activity"

    if risk_level == "medium":

        return "review_suspicious_activity"

    if detection_status == "suspicious":

        return "monitor_suspicious_activity"

    if not context_known:

        return "monitor_and_verify_device"

    return "record_and_monitor"


# --------------------------------------------------
# CONTEXT-AWARE RISK ASSESSMENT
# --------------------------------------------------

def assess_prediction_risk(

    prediction: dict,

    device_id: str | None = None,

) -> dict:

    context = get_device_context(
        device_id
    )

    impact_result = calculate_attack_impact(

        prediction["class_probabilities"]
    )

    probability = validate_unit_value(

        prediction["calibrated_attack_probability"],

        "attack_probability",
    )

    criticality = context["criticality"]

    exposure = context["exposure"]

    attack_impact = impact_result[
        "expected_impact"
    ]

    risk_score = calculate_risk_score(

        attack_probability=probability,

        criticality=criticality,

        attack_impact=attack_impact,

        exposure=exposure,
    )

    risk_level = get_risk_level(
        risk_score
    )

    # Explain each factor's contribution
    # to the final risk score.

    criticality_contribution = (

        100 * probability

        * RISK_WEIGHTS["criticality"]

        * criticality
    )

    impact_contribution = (

        100 * probability

        * RISK_WEIGHTS["attack_impact"]

        * attack_impact
    )

    exposure_contribution = (

        100 * probability

        * RISK_WEIGHTS["exposure"]

        * exposure
    )

    contribution_sum = (

        criticality_contribution

        + impact_contribution

        + exposure_contribution
    )

    recommendation = recommend_action(

        risk_level=risk_level,

        detection_status=prediction[
            "detection_status"
        ],

        context_known=context[
            "context_known"
        ],
    )

    warnings = [

        "Risk weights and thresholds are "
        "provisional policy parameters.",

        "Device context is demonstration-only.",

        "Attack probability calibration "
        "has not been independently evaluated.",
    ]

    if not context["context_known"]:

        warnings.append(

            "Unknown device: fallback criticality "
            "and exposure were used."
        )

    if not impact_result["impact_available"]:

        warnings.append(

            "No meaningful raw attack-class "
            "probability mass was available "
            "for impact estimation."
        )

    if prediction["candidate_attack_family"] == "BruteForce":

        warnings.append(

            "BruteForce detection has no "
            "independent validation coverage."
        )

    return {

        "risk_policy_version":
            RISK_POLICY_VERSION,

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "attack_probability":
            probability,

        "device_context":
            context,

        "attack_impact":
            impact_result,

        "risk_factors": {

            "criticality":
                criticality,

            "attack_impact":
                attack_impact,

            "exposure":
                exposure,
        },

        "risk_weights":
            RISK_WEIGHTS.copy(),

        "risk_contributions": {

            "criticality":
                criticality_contribution,

            "attack_impact":
                impact_contribution,

            "exposure":
                exposure_contribution,
        },

        "risk_reconstruction": {

            "contribution_sum":
                contribution_sum,

            "error":
                abs(contribution_sum - risk_score),

            "passed":
                math.isclose(

                    contribution_sum,

                    risk_score,

                    abs_tol=1e-8,

                    rel_tol=0,
                ),
        },

        "recommended_action":
            recommendation,

        "requires_device_verification":
            not context["identity_verified"],

        "containment_authorized":
            False,

        "response_executed":
            False,

        "warnings":
            warnings,
    }


# --------------------------------------------------
# COMPLETE PREDICTION AND RISK PIPELINE
# --------------------------------------------------

def assess_traffic_risk(

    features: dict,

    device_id: str | None = None,

) -> dict:

    prediction = predict_traffic(
        features
    )

    risk = assess_prediction_risk(

        prediction=prediction,

        device_id=device_id,
    )

    return {

        "prediction": prediction,

        "risk_assessment": risk,

        "mode": "risk_assessment_only",

        "incident_created": False,

        "response_executed": False,
    }