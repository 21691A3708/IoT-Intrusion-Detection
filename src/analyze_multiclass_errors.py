from pathlib import Path

import pandas as pd
import numpy as np

from multiclass_label_mapping import ID_TO_LABEL


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT / "data" / "processed" / "multiclass"
)

RESULTS_DIR = (
    PROJECT_ROOT / "results" / "multiclass"
)

OUTPUT_DIR = RESULTS_DIR / "error_analysis"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main():

    print("=" * 75)
    print("MULTICLASS ERROR ANALYSIS")
    print("=" * 75)

    manifest = pd.read_csv(
        RESULTS_DIR / "capture_split.csv"
    )

    # Inspect original attack subtype allocation.
    coverage = pd.crosstab(
        [
            manifest["AttackFamily"],
            manifest["OriginalAttack"],
        ],
        manifest["Split"],
    ).reindex(
        columns=["train", "validation", "test"],
        fill_value=0,
    )

    print("\nATTACK SUBTYPE CAPTURE COVERAGE")
    print(coverage.to_string())

    coverage.to_csv(
        OUTPUT_DIR / "subtype_capture_coverage.csv"
    )

    # Identify validation subtypes not seen in training.
    unseen = coverage[
        (coverage["train"] == 0)
        & (coverage["validation"] > 0)
    ]

    print("\nUNSEEN VALIDATION ATTACK SUBTYPES")

    if unseen.empty:
        print("None")
    else:
        print(unseen.to_string())

    unseen.to_csv(
        OUTPUT_DIR / "unseen_validation_subtypes.csv"
    )

    # Load metadata in the same row order used
    # by both training programs.
    train = pd.read_csv(
        DATA_DIR / "verified" / "train.csv",
        usecols=[
            "Label",
            "AttackFamily",
            "OriginalAttack",
            "SourceCapture",
        ],
    )

    validation = pd.read_csv(
        DATA_DIR / "verified" / "validation.csv",
        usecols=[
            "Label",
            "AttackFamily",
            "OriginalAttack",
            "SourceCapture",
        ],
    )

    training_subtypes = set(
        train["OriginalAttack"].unique()
    )

    validation["SeenInTraining"] = (
        validation["OriginalAttack"].isin(
            training_subtypes
        )
    )

    model_folders = {
        "Random Forest": "random_forest",
        "XGBoost": "xgboost",
    }

    all_reports = []

    for model_name, folder in model_folders.items():

        print("\n" + "=" * 75)
        print(model_name.upper())
        print("=" * 75)

        predictions = pd.read_csv(
            RESULTS_DIR
            / folder
            / "validation_predictions.csv"
        )

        if len(predictions) != len(validation):
            raise ValueError(
                "Prediction and validation row counts differ."
            )

        if not np.array_equal(
            predictions["ActualLabel"].to_numpy(),
            validation["Label"].to_numpy(),
        ):
            raise ValueError(
                "Prediction row alignment failed."
            )

        analysis = validation.copy()

        analysis["PredictedLabel"] = (
            predictions["PredictedLabel"].to_numpy()
        )

        analysis["PredictedFamily"] = (
            analysis["PredictedLabel"].map(ID_TO_LABEL)
        )

        analysis["Correct"] = (
            analysis["Label"]
            == analysis["PredictedLabel"]
        )

        analysis["Confidence"] = (
            predictions["PredictionConfidence"].to_numpy()
        )

        subtype_report = (
            analysis.groupby(
                [
                    "AttackFamily",
                    "OriginalAttack",
                    "SeenInTraining",
                ]
            )
            .agg(
                Records=("Correct", "size"),
                Correct=("Correct", "sum"),
                Recall=("Correct", "mean"),
                MeanConfidence=("Confidence", "mean"),
            )
            .reset_index()
        )

        subtype_report["Model"] = model_name

        all_reports.append(subtype_report)

        print("\nPER-SUBTYPE PERFORMANCE")

        print(
            subtype_report.round(4).to_string(
                index=False
            )
        )

        # Find the most common incorrect predictions.
        errors = analysis.loc[
            ~analysis["Correct"]
        ]

        confusion = pd.crosstab(
            errors["AttackFamily"],
            errors["PredictedFamily"],
        )

        print("\nINCORRECT CLASSIFICATIONS")

        print(confusion.to_string())

        confusion.to_csv(
            OUTPUT_DIR
            / f"{folder}_misclassifications.csv"
        )

        print("\nSPOOFING PREDICTIONS")

        print(
            analysis.loc[
                analysis["AttackFamily"] == "Spoofing",
                "PredictedFamily",
            ].value_counts().to_string()
        )

        print("\nRECONNAISSANCE PREDICTIONS")

        print(
            analysis.loc[
                analysis["AttackFamily"]
                == "Reconnaissance",
                "PredictedFamily",
            ].value_counts().to_string()
        )

        print("\nBENIGN FALSE POSITIVES")

        benign_errors = errors[
            errors["AttackFamily"] == "Benign"
        ]

        print(
            benign_errors["PredictedFamily"]
            .value_counts()
            .to_string()
        )

        capture_report = (
            analysis.groupby(
                ["SourceCapture", "AttackFamily"]
            )
            .agg(
                Records=("Correct", "size"),
                Recall=("Correct", "mean"),
                MeanConfidence=("Confidence", "mean"),
            )
            .reset_index()
        )

        capture_report.to_csv(
            OUTPUT_DIR
            / f"{folder}_capture_performance.csv",
            index=False,
        )

    final_report = pd.concat(
        all_reports,
        ignore_index=True,
    )

    final_report.to_csv(
        OUTPUT_DIR / "subtype_performance.csv",
        index=False,
    )

    print("\n" + "=" * 75)
    print("ERROR ANALYSIS COMPLETED")
    print("=" * 75)

    print("Reports saved:", OUTPUT_DIR)


if __name__ == "__main__":
    main()