import math
from numbers import Real


ATTACK_IMPACT = {

    "DDoS": 0.90,

    "DoS": 0.75,

    "Reconnaissance": 0.40,

    "BruteForce": 0.70,

    "Spoofing": 0.80,

    "Mirai": 0.95,

    "WebBased": 0.85,
}


def calculate_attack_impact(
    class_probabilities: dict,
) -> dict:

    if not isinstance(
        class_probabilities, dict
    ):

        raise ValueError(
            "Class probabilities must be a dictionary."
        )

    expected_classes = (
        set(ATTACK_IMPACT) | {"Benign"}
    )

    if set(class_probabilities) != expected_classes:

        raise ValueError(
            "Unexpected class probability schema."
        )

    probabilities = {}

    for family, value in class_probabilities.items():

        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
        ):

            raise ValueError(
                f"Invalid probability for {family}."
            )

        probability = float(value)

        if (
            not math.isfinite(probability)
            or not 0 <= probability <= 1
        ):

            raise ValueError(
                f"Invalid probability for {family}."
            )

        probabilities[family] = probability

    if not math.isclose(
        sum(probabilities.values()),
        1.0,
        abs_tol=1e-6,
        rel_tol=0,
    ):

        raise ValueError(
            "Class probabilities must sum to one."
        )

    raw_attack_probability = sum(

        probabilities[family]

        for family in ATTACK_IMPACT
    )

    contributions = []

    if raw_attack_probability <= 1e-12:

        return {

            "expected_impact": 0.0,

            "raw_attack_probability":
                raw_attack_probability,

            "impact_contributions": [],

            "impact_available": False,

            "impact_policy_version":
                "attack_impact_v1",
        }

    expected_impact = 0.0

    for family, impact in ATTACK_IMPACT.items():

        conditional_probability = (

            probabilities[family]

            / raw_attack_probability
        )

        contribution = (

            conditional_probability * impact
        )

        expected_impact += contribution

        contributions.append({

            "attack_family": family,

            "class_probability":
                probabilities[family],

            "conditional_probability":
                conditional_probability,

            "impact_score": impact,

            "weighted_contribution":
                contribution,
        })

    contributions.sort(

        key=lambda item:
            item["weighted_contribution"],

        reverse=True,
    )

    return {

        "expected_impact":
            float(expected_impact),

        "raw_attack_probability":
            raw_attack_probability,

        "impact_contributions":
            contributions,

        "impact_available": True,

        "impact_policy_version":
            "attack_impact_v1",

        "class_probabilities_calibrated":
            False,
    }