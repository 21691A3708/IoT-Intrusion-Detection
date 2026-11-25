from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RESULTS_DIR = (

    PROJECT_ROOT

    / "results/multiclass/context_risk"
)


def main():

    df = pd.read_csv(

        RESULTS_DIR / "risk_assessment_summary.csv"
    )

    # ----------------------------------------------
    # GRAPH 1: RISK SCORE HEATMAP
    # ----------------------------------------------

    matrix = df.pivot(

        index="ActualFamily",

        columns="DeviceName",

        values="RiskScore",
    )

    fig, ax = plt.subplots(

        figsize=(13, 7)
    )

    image = ax.imshow(

        matrix.values,

        cmap="RdYlGn_r",

        vmin=0,

        vmax=100,

        aspect="auto",
    )

    ax.set_xticks(

        range(len(matrix.columns)),

        labels=matrix.columns,

        rotation=30,

        ha="right",
    )

    ax.set_yticks(

        range(len(matrix.index)),

        labels=matrix.index,
    )

    for i in range(len(matrix.index)):

        for j in range(len(matrix.columns)):

            ax.text(

                j,

                i,

                f"{matrix.iloc[i, j]:.1f}",

                ha="center",

                va="center",

                fontsize=10,
            )

    fig.colorbar(

        image,

        ax=ax,

        label="Context-aware risk score",
    )

    ax.set_title(

        "Context-Aware Risk Across Attack Samples "
        "and Device Profiles"
    )

    ax.set_xlabel("Demonstration device")

    ax.set_ylabel("Actual traffic family")

    fig.tight_layout()

    fig.savefig(

        RESULTS_DIR / "context_risk_heatmap.png",

        dpi=300,
    )

    plt.close(fig)

    # ----------------------------------------------
    # GRAPH 2: SAME ATTACK, DIFFERENT DEVICES
    # ----------------------------------------------

    mirai = df[

        df["ActualFamily"] == "Mirai"

    ].sort_values("RiskScore")

    fig, ax = plt.subplots(

        figsize=(11, 6)
    )

    colors = {

        "low": "#2ca02c",

        "medium": "#d4a017",

        "high": "#ff7f0e",

        "critical": "#d62728",
    }

    bars = ax.barh(

        mirai["DeviceName"],

        mirai["RiskScore"],

        color=[

            colors[level]

            for level in mirai["RiskLevel"]
        ],
    )

    ax.bar_label(

        bars,

        fmt="%.2f",

        padding=3,
    )

    for threshold in [25, 50, 75]:

        ax.axvline(

            threshold,

            linestyle="--",

            color="gray",

            alpha=0.6,
        )

    ax.set_xlim(0, 105)

    ax.set_xlabel("Risk score")

    ax.set_title(

        "Same Mirai Traffic Record, "
        "Different Device Contexts"
    )

    fig.tight_layout()

    fig.savefig(

        RESULTS_DIR / "mirai_device_risk_comparison.png",

        dpi=300,
    )

    plt.close(fig)

    # ----------------------------------------------
    # GRAPH 3: PROBABILITY VS CONTEXT RISK
    # ----------------------------------------------

    fig, ax = plt.subplots(

        figsize=(12, 7)
    )

    for device, group in df.groupby("DeviceName"):

        ax.scatter(

            group["AttackProbability"] * 100,

            group["RiskScore"],

            label=device,

            s=60,

            alpha=0.8,
        )

    ax.plot(

        [0, 100],

        [0, 100],

        linestyle="--",

        color="black",

        label="Probability-only score",
    )

    ax.set_xlim(0, 105)

    ax.set_ylim(0, 105)

    ax.set_xlabel(

        "Probability-only score (100 × P)"
    )

    ax.set_ylabel("Context-aware risk score")

    ax.set_title(

        "Probability-Only vs Context-Aware Risk"
    )

    ax.legend()

    ax.grid(alpha=0.2)

    fig.tight_layout()

    fig.savefig(

        RESULTS_DIR / "probability_vs_context_risk.png",

        dpi=300,
    )

    plt.close(fig)

    print("=" * 75)
    print("CONTEXT RISK VISUALIZATION COMPLETED")
    print("=" * 75)

    print("Generated:")

    print("1. context_risk_heatmap.png")

    print("2. mirai_device_risk_comparison.png")

    print("3. probability_vs_context_risk.png")

    print("\nOutput directory:", RESULTS_DIR)


if __name__ == "__main__":

    main()