from pathlib import Path
import json

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
    / "multiclass"
    / "explainability"
)

INPUT_FILE = (
    RESULTS_DIR
    / "sample_explanations.json"
)

OUTPUT_DIR = (
    RESULTS_DIR
    / "plots"
)

TOP_N = 10


def plot_explanation(
    explanation,
    actual_family,
    predicted_family,
    explanation_type,
):

    features = explanation[
        "all_features"
    ][:TOP_N]

    features = list(
        reversed(features)
    )

    names = [
        item["feature"]
        for item in features
    ]

    values = [
        item["shap_value"]
        for item in features
    ]

    colors = [

        "#d62728" if value > 0

        else "#1f77b4" if value < 0

        else "#999999"

        for value in values
    ]

    fig, ax = plt.subplots(
        figsize=(11, 7)
    )

    ax.barh(
        names,
        values,
        color=colors,
    )

    ax.axvline(
        0,
        color="black",
        linewidth=0.8,
    )

    target = explanation[
        "explained_target"
    ]

    ax.set_title(

        f"SHAP {explanation_type} Explanation\n"

        f"Actual: {actual_family} | "

        f"Predicted: {predicted_family}\n"

        f"Explained target: {target}",

        fontsize=13,
    )

    ax.set_xlabel(
        "SHAP contribution to raw probability"
    )

    ax.set_ylabel(
        "Network traffic features"
    )

    ax.grid(
        axis="x",
        alpha=0.2,
    )

    fig.text(

        0.5,
        0.035,

        f"Baseline: "
        f"{explanation['base_value']:.6f} | "

        f"Raw probability: "
        f"{explanation['target_probability']:.6f}",

        ha="center",
        fontsize=10,
    )

    fig.text(

        0.5,
        0.01,

        "Red: increases explained probability | "
        "Blue: decreases explained probability",

        ha="center",
        fontsize=9,
    )

    fig.tight_layout(
        rect=[0, 0.08, 1, 1]
    )

    output_path = (

        OUTPUT_DIR

        / (
            f"{actual_family}_"
            f"{explanation_type.lower()}.png"
        )
    )

    fig.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight",
    )

    plt.close(fig)

    print(
        f"Saved: {output_path.name}"
    )


def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        INPUT_FILE,
        encoding="utf-8",
    ) as file:

        samples = json.load(file)

    print("=" * 75)
    print("MULTICLASS SHAP VISUALIZATION")
    print("=" * 75)

    for sample in samples:

        actual = sample[
            "actual_family"
        ]

        result = sample["result"]

        predicted = result[
            "prediction"
        ]["predicted_family"]

        plot_explanation(

            result["family_explanation"],

            actual,

            predicted,

            "Family",
        )

        plot_explanation(

            result["attack_explanation"],

            actual,

            predicted,

            "Attack",
        )

    print("\nVisualization completed.")

    print(
        f"Generated {len(samples) * 2} plots."
    )

    print(
        f"Output directory: {OUTPUT_DIR}"
    )


if __name__ == "__main__":
    main()