from pathlib import Path

import pandas as pd

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RESULTS_DIR = (
    PROJECT_ROOT / "results" / "multiclass"
)

OUTPUT_DIR = RESULTS_DIR / "comparison"

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

MODEL_FOLDERS = {
    "Random Forest": "random_forest",
    "XGBoost": "xgboost",
}

METRICS = [
    "Accuracy",
    "BalancedAccuracy",
    "MacroPrecision",
    "MacroRecall",
    "MacroF1",
    "WeightedF1",
    "LogLoss",
    "AttackFalsePositiveRate",
    "TrainingSeconds",
    "PredictionSeconds",
]


def main():

    records = []

    recall_records = {}

    for model_name, folder in MODEL_FOLDERS.items():

        metrics_path = (
            RESULTS_DIR / folder / "metrics.csv"
        )

        report_path = (
            RESULTS_DIR
            / folder
            / "classification_report.csv"
        )

        if not metrics_path.is_file():
            raise FileNotFoundError(metrics_path)

        metrics = pd.read_csv(
            metrics_path
        ).iloc[0].to_dict()

        metrics["Model"] = model_name

        records.append(metrics)

        report = pd.read_csv(
            report_path,
            index_col=0,
        )

        supported = report[
            report.index.isin([
                "Benign",
                "DDoS",
                "DoS",
                "Reconnaissance",
                "BruteForce",
                "Spoofing",
                "Mirai",
                "WebBased",
            ])
        ]

        supported = supported[
            supported["support"] > 0
        ]

        recall_records[model_name] = (
            supported["recall"]
        )

    comparison = pd.DataFrame(records)

    for column in [
        "TrainingRows",
        "ValidationRows",
        "FeatureCount",
        "EvaluatedClasses",
        "EvaluationSplit",
    ]:

        if comparison[column].nunique() != 1:
            raise ValueError(
                f"Inconsistent evaluation setup: {column}"
            )

    comparison = comparison.set_index("Model")

    comparison = comparison[METRICS]

    print("=" * 75)
    print("MULTICLASS MODEL COMPARISON")
    print("=" * 75)

    print(
        comparison.transpose().round(6).to_string()
    )

    comparison.to_csv(
        OUTPUT_DIR / "model_comparison.csv"
    )

    # Compare classification metrics.
    plot_metrics = [
        "Accuracy",
        "BalancedAccuracy",
        "MacroF1",
        "WeightedF1",
    ]

    ax = comparison[plot_metrics].transpose().plot(
        kind="bar",
        figsize=(10, 6),
        rot=0,
    )

    ax.set_ylim(0, 1.1)

    ax.set_ylabel("Score")

    ax.set_title(
        "Random Forest vs XGBoost - Validation"
    )

    for container in ax.containers:

        ax.bar_label(
            container,
            fmt="%.3f",
            padding=3,
        )

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "performance_comparison.png",
        dpi=300,
    )

    plt.close()

    # Compare per-class recall.
    recall_df = pd.DataFrame(
        recall_records
    )

    print("\nPER-CLASS RECALL")

    print(
        recall_df.round(4).to_string()
    )

    recall_df.to_csv(
        OUTPUT_DIR / "class_recall_comparison.csv"
    )

    ax = recall_df.plot(
        kind="bar",
        figsize=(12, 6),
        rot=30,
    )

    ax.set_ylim(0, 1.1)

    ax.set_ylabel("Recall")

    ax.set_title(
        "Attack Family Recall Comparison"
    )

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "class_recall_comparison.png",
        dpi=300,
    )

    plt.close()

    best_macro_f1 = comparison["MacroF1"].idxmax()

    lowest_fpr = comparison[
        "AttackFalsePositiveRate"
    ].idxmin()

    print("\nHighest Macro F1:", best_macro_f1)

    print("Lowest attack false-positive rate:", lowest_fpr)

    print(
        "\nFinal model selection must also consider "
        "minority-class recall, calibration, "
        "inference cost and explainability."
    )

    print(
        "\nComparison results saved:",
        OUTPUT_DIR
    )


if __name__ == "__main__":
    main()