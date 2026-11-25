import math


def calibrate_attack_probability(
    raw_probability: float,
    parameters: dict,
) -> float:

    probability = float(raw_probability)

    if not math.isfinite(probability):
        raise ValueError(
            "Attack probability must be finite."
        )

    if not 0.0 <= probability <= 1.0:
        raise ValueError(
            "Attack probability must be between 0 and 1."
        )

    if parameters.get("method") != "sigmoid_on_logit":
        raise ValueError(
            "Unsupported calibration method."
        )

    coefficient = float(
        parameters["coefficient"]
    )

    intercept = float(
        parameters["intercept"]
    )

    epsilon = float(
        parameters.get("epsilon", 1e-6)
    )

    if not all(
        math.isfinite(value)
        for value in [
            coefficient,
            intercept,
            epsilon,
        ]
    ):
        raise ValueError(
            "Invalid calibration parameters."
        )

    if not 0 < epsilon < 0.5:
        raise ValueError(
            "Invalid calibration epsilon."
        )

    probability = min(
        max(probability, epsilon),
        1.0 - epsilon,
    )

    logit = math.log(
        probability / (1.0 - probability)
    )

    z = coefficient * logit + intercept

    # Numerically stable sigmoid.
    if z >= 0:
        return 1.0 / (
            1.0 + math.exp(-z)
        )

    exp_z = math.exp(z)

    return exp_z / (1.0 + exp_z)