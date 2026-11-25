from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
    / "multiclass"
    / "calibration"
)

INPUT_PATH = (
    RESULTS_DIR
    / "calibrated_validation_predictions.csv"
)


def main():

    df = pd.read_csv(INPUT_PATH)

    y_true = df["ActualAttack"].to_numpy()

    probabilities = df[
        "CalibratedAttackProbability"
    ].to_numpy()

    thresholds = [
        0.30,
        0.40,
        0.50,
        0.60,
        0.70,
        0.75,
        0.80,
        0.85,
        0.90,
        0.95,
        0.99,
    ]

    results = []

    print("=" * 75)
    print("ATTACK DECISION THRESHOLD ANALYSIS")
    print("=" * 75)

    for threshold in thresholds:

        predictions = (
            probabilities >= threshold
        ).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            y_true,
            predictions,
            labels=[0, 1],
        ).ravel()

        fpr = fp / (fp + tn)

        fnr = fn / (fn + tp)

        spoofing_mask = (
            df["ActualLabel"].to_numpy() == 5
        )

        recon_mask = (
            df["ActualLabel"].to_numpy() == 3
        )

        results.append({

            "Threshold": threshold,

            "Precision": precision_score(
                y_true,
                predictions,
                zero_division=0,
            ),

            "AttackRecall": recall_score(
                y_true,
                predictions,
                zero_division=0,
            ),

            "F1": f1_score(
                y_true,
                predictions,
                zero_division=0,
            ),

            "FalsePositiveRate": fpr,

            "FalseNegativeRate": fnr,

            "SpoofingDetectionRecall": (
                predictions[spoofing_mask].mean()
                if spoofing_mask.any()
                else np.nan
            ),

            "ReconDetectionRecall": (
                predictions[recon_mask].mean()
                if recon_mask.any()
                else np.nan
            ),

            "FalsePositives": int(fp),

            "FalseNegatives": int(fn),

        })

    results_df = pd.DataFrame(results)

    print(
        results_df.round(6).to_string(
            index=False
        )
    )

    output_path = (
        RESULTS_DIR
        / "threshold_analysis.csv"
    )

    results_df.to_csv(
        output_path,
        index=False,
    )

    # Find candidate thresholds with <= 5% FPR.

    candidates = results_df[
        results_df["FalsePositiveRate"] <= 0.05
    ]

    print("\nCANDIDATE THRESHOLDS")

    if candidates.empty:

        print(
            "No evaluated threshold achieved "
            "the proposed 5% FPR target."
        )

    else:

        candidates = candidates.sort_values(
            ["AttackRecall", "FalsePositiveRate"],
            ascending=[False, True],
        )

        print(
            candidates.round(6).to_string(
                index=False
            )
        )

        print(
            "\nHighest attack recall among "
            "these candidates:"
        )

        print(
            candidates.iloc[0].to_string()
        )

    print("\nResults saved:", output_path)

    print(
        "\nThese are development diagnostics, "
        "not independent test results."
    )

    print(
        "No threshold has been automatically "
        "activated in the backend."
    )


if __name__ == "__main__":
    main()