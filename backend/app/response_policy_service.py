
import math

from .context_risk_service import (
    assess_traffic_risk,
    validate_unit_value,
    get_risk_level,
)

from .multiclass_ml_service import (
    get_model_info,
)


RESPONSE_POLICY_VERSION = "controlled_response_v1"

MIN_ATTACK_PROBABILITY = 0.90
MIN_FAMILY_CONFIDENCE = 0.70
MIN_CONTAINMENT_RISK = 75.0


# --------------------------------------------------
# ATTACK-SPECIFIC RESPONSE RECOMMENDATIONS
# --------------------------------------------------

ATTACK_RESPONSE_POLICIES = {
    "Benign": {
        "recommendation": "Monitor network activity.",
        "containment_action": None,
    },

    "DDoS": {
        "recommendation": (
            "Investigate distributed traffic sources "
            "and review traffic filtering policies."
        ),
        "containment_action": "simulate_rate_limiting",
    },

    "DoS": {
        "recommendation": (
            "Investigate excessive traffic and "
            "review service availability."
        ),
        "containment_action": "simulate_rate_limiting",
    },

    "Reconnaissance": {
        "recommendation": (
            "Investigate scanning activity and "
            "monitor exposed services."
        ),
        "containment_action": None,
    },

    "BruteForce": {
        "recommendation": (
            "Review authentication attempts "
            "and account security."
        ),
        "containment_action": None,
    },

    "Spoofing": {
        "recommendation": (
            "Verify network identities and "
            "address mappings."
        ),
        "containment_action": None,
    },

    "Mirai": {
        "recommendation": (
            "Investigate possible botnet compromise "
            "and assess device isolation."
        ),
        "containment_action": "simulate_device_isolation",
    },

    "WebBased": {
        "recommendation": (
            "Review application traffic and "
            "application security policies."
        ),
        "containment_action": "simulate_traffic_filtering",
    },
}


# --------------------------------------------------
# POLICY INFORMATION
# --------------------------------------------------

def get_response_policy_info() -> dict:

    return {
        "response_policy_version":
            RESPONSE_POLICY_VERSION,

        "minimum_attack_probability":
            MIN_ATTACK_PROBABILITY,

        "minimum_family_confidence":
            MIN_FAMILY_CONFIDENCE,

        "minimum_containment_risk":
            MIN_CONTAINMENT_RISK,

        "requires_known_device": True,

        "requires_verified_identity": True,

        "requires_device_permission": True,

        "requires_analyst_approval": True,

        "simulation_only": True,

        "real_network_execution_enabled": False,
    }


# --------------------------------------------------
# RESPONSE POLICY EVALUATION
# --------------------------------------------------

def evaluate_response_policy(
    prediction: dict,
    risk_assessment: dict,
) -> dict:

    probability = validate_unit_value(
        prediction["calibrated_attack_probability"],
        "attack_probability",
    )

    confidence = validate_unit_value(
        prediction["prediction_confidence"],
        "prediction_confidence",
    )

    risk_score = 100 * validate_unit_value(
        risk_assessment["risk_score"] / 100,
        "normalized_risk_score",
    )

    risk_level = get_risk_level(risk_score)

    if risk_level != risk_assessment["risk_level"]:
        raise ValueError(
            "Risk score and risk level are inconsistent."
        )

    if not math.isclose(
        probability,
        risk_assessment["attack_probability"],
        abs_tol=1e-8,
        rel_tol=0,
    ):
        raise ValueError(
            "Prediction and risk probabilities differ."
        )

    predicted_family = prediction["predicted_family"]

    if predicted_family not in ATTACK_RESPONSE_POLICIES:
        raise ValueError("Unknown attack family.")

    context = risk_assessment["device_context"]

    # Retrieve validation coverage from model metadata.
    model_info = get_model_info()

    supported_labels = model_info[
        "validation_supported_labels"
    ]

    family_supported = (
        prediction["predicted_label"]
        in supported_labels
    )

    attack_policy = ATTACK_RESPONSE_POLICIES[
        predicted_family
    ]

    proposed_action = attack_policy[
        "containment_action"
    ]

    # --------------------------------------------------
    # INCIDENT ELIGIBILITY
    # --------------------------------------------------

    incident_required = (
        risk_level in ("high", "critical")
        or probability >= MIN_ATTACK_PROBABILITY
    )

    if risk_level == "critical":

        primary_action = "priority_investigation"

    elif incident_required:

        primary_action = "alert_and_investigate"

    elif risk_level == "medium":

        primary_action = "review_suspicious_activity"

    else:

        primary_action = risk_assessment[
            "recommended_action"
        ]

    # --------------------------------------------------
    # SAFETY CHECKS
    # --------------------------------------------------

    safety_checks = {

        "attack_probability_sufficient":
            probability >= MIN_ATTACK_PROBABILITY,

        "risk_score_sufficient":
            risk_score >= MIN_CONTAINMENT_RISK,

        "family_confidence_sufficient":
            confidence >= MIN_FAMILY_CONFIDENCE,

        "attack_family_predicted":
            predicted_family != "Benign",

        "family_has_validation_coverage":
            family_supported,

        "device_context_known":
            context.get("context_known") is True,

        "device_identity_verified":
            context.get("identity_verified") is True,

        "device_containment_allowed":
            context.get("containment_allowed") is True,

        "device_identifier_available":
            isinstance(context.get("device_id"), str)
            and bool(context["device_id"].strip()),

        "attack_impact_available":
            risk_assessment["attack_impact"].get(
                "impact_available"
            ) is True,

        "containment_action_available":
            proposed_action is not None,
    }

    restriction_reasons = [

        name

        for name, passed in safety_checks.items()

        if not passed
    ]

    containment_eligible = all(
        safety_checks.values()
    )

    # --------------------------------------------------
    # RESPONSE DECISION
    # --------------------------------------------------

    if containment_eligible:

        response_status = "pending_approval"

    elif proposed_action is not None:

        response_status = "restricted"

    else:

        response_status = "not_required"

    # --------------------------------------------------
    # POLICY RESULT
    # --------------------------------------------------

    return {

        "response_policy_version":
            RESPONSE_POLICY_VERSION,

        "model_version":
            prediction["model_version"],

        "risk_policy_version":
            risk_assessment["risk_policy_version"],

        "predicted_family":
            predicted_family,

        "attack_probability":
            probability,

        "family_confidence":
            confidence,

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "device_id":
            context.get("device_id"),

        "device_name":
            context.get("device_name"),

        "incident_required":
            incident_required,

        "primary_action":
            primary_action,

        "attack_specific_recommendation":
            attack_policy["recommendation"],

        "proposed_containment_action":
            proposed_action,

        "eligible_containment_action":
            proposed_action
            if containment_eligible
            else None,

        "containment_eligible":
            containment_eligible,

        "approval_required":
            containment_eligible,

        "approval_granted":
            False,

        "containment_authorized":
            False,

        "response_status":
            response_status,

        "requires_device_verification":
            context.get("identity_verified") is not True,

        "safety_checks":
            safety_checks,

        "restriction_reasons":
            restriction_reasons,

        "simulation_only":
            True,

        "response_executed":
            False,

        "real_network_action_executed":
            False,

        "warnings": [
            "Policy thresholds are provisional.",
            "Validation coverage does not guarantee "
            "correct attack classification.",
            "Containment requires analyst approval.",
            "No real network actions are permitted.",
        ],
    }


# --------------------------------------------------
# INTEGRATED RESPONSE PLANNING PIPELINE
# --------------------------------------------------

def plan_traffic_response(
    features: dict,
    device_id: str | None = None,
) -> dict:

    assessment = assess_traffic_risk(
        features=features,
        device_id=device_id,
    )

    prediction = assessment["prediction"]

    risk = assessment["risk_assessment"]

    response_plan = evaluate_response_policy(
        prediction=prediction,
        risk_assessment=risk,
    )

    return {
        "prediction": prediction,

        "risk_assessment": risk,

        "response_plan": response_plan,

        "mode": "response_planning_only",

        "incident_created": False,

        "response_executed": False,
    }
