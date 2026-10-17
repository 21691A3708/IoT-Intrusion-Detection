
from pathlib import Path

import pandas as pd
import streamlit as st
import joblib

# --------------------------------------------------
# Configuration
# --------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_DIR / "results" / "incident_response"

INTEGRATED_REPORT = RESULTS_DIR / "integrated_incident_report.csv"
INCIDENT_REPORT = RESULTS_DIR / "incident_report.csv"
SHAP_REPORT = RESULTS_DIR / "shap_incident_explanation.csv"

st.set_page_config(
    page_title="IoT Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
)

# --------------------------------------------------
# Data loading
# --------------------------------------------------
@st.cache_data
def load_csv(path_string):
    path = Path(path_string)
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def load_incidents():
    # Prefer the complete incident report for overview metrics.
    # The integrated report contains additional SHAP explanations.
    if INCIDENT_REPORT.exists():
        return load_csv(str(INCIDENT_REPORT))
    if INTEGRATED_REPORT.exists():
        return load_csv(str(INTEGRATED_REPORT))
    return pd.DataFrame()


incidents = load_incidents()
integrated = load_csv(str(INTEGRATED_REPORT))
shap_data = load_csv(str(SHAP_REPORT))

# --------------------------------------------------
# Sidebar
# --------------------------------------------------
st.sidebar.title("🛡️ IoT Security")
page = st.sidebar.radio(
    "Navigation",
  [
    "Dashboard",
    "Live Prediction",
    "Incident Explorer",
    "Explainability",
    "Project Information",
],
)

st.sidebar.divider()
st.sidebar.caption("AI-Based IoT Intrusion Detection")
st.sidebar.caption("Risk-aware incident response")

# --------------------------------------------------
# Header
# --------------------------------------------------
st.title("IoT Intrusion Detection & Incident Response")
st.caption(
    "Explainable machine-learning detection, risk assessment, "
    "and incident analysis."
)

if incidents.empty:
    st.error(
        "No incident report was found. Check that the CSV files "
        "exist in results/incident_response/."
    )
    st.stop()

# --------------------------------------------------
# Normalize columns
# --------------------------------------------------
required_columns = [
    "PredictedClass",
    "AttackProbability",
    "RiskScore",
    "RiskLevel",
]

missing_columns = [
    column for column in required_columns
    if column not in incidents.columns
]

if missing_columns:
    st.error(f"Missing required report columns: {missing_columns}")
    st.stop()

incidents = incidents.copy()
incidents["AttackProbability"] = pd.to_numeric(
    incidents["AttackProbability"], errors="coerce"
)
incidents["RiskScore"] = pd.to_numeric(
    incidents["RiskScore"], errors="coerce"
)
incidents["PredictedClass"] = pd.to_numeric(
    incidents["PredictedClass"], errors="coerce"
)
incidents["RiskLevel"] = (
    incidents["RiskLevel"].fillna("Unknown").astype(str).str.upper()
)

if "RecordIndex" in incidents.columns:
    incidents["RecordIndex"] = incidents["RecordIndex"].astype(str)

# --------------------------------------------------
# Dashboard page
# --------------------------------------------------
if page == "Dashboard":
    st.subheader("Security Overview")

    total_records = len(incidents)
    attack_count = int((incidents["PredictedClass"] == 1).sum())
    normal_count = int((incidents["PredictedClass"] == 0).sum())
    high_critical = int(
        incidents["RiskLevel"].isin(["HIGH", "CRITICAL"]).sum()
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Records Analyzed", f"{total_records:,}")
    col2.metric("Predicted Attacks", f"{attack_count:,}")
    col3.metric("Predicted Normal", f"{normal_count:,}")
    col4.metric("High / Critical Risk", f"{high_critical:,}")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Risk Distribution")
        risk_counts = (
            incidents["RiskLevel"]
            .value_counts()
            .reindex(
                ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"],
                fill_value=0,
            )
        )
        st.bar_chart(risk_counts)

    with right:
        st.subheader("Prediction Distribution")
        prediction_counts = pd.Series(
            {
                "Normal": normal_count,
                "Attack": attack_count,
            }
        )
        st.bar_chart(prediction_counts)

    st.subheader("Recent High-Risk Incidents")
    high_risk = incidents[
        incidents["RiskLevel"].isin(["HIGH", "CRITICAL"])
    ].copy()

    display_columns = [
        column for column in [
            "RecordIndex",
            "PredictedClass",
            "AttackProbability",
            "RiskScore",
            "RiskLevel",
            "RecommendedAction",
            "ResponseMode",
        ]
        if column in high_risk.columns
    ]

    if high_risk.empty:
        st.info("No High or Critical incidents appear in this report.")
    else:
        st.dataframe(
            high_risk[display_columns].head(20),
            use_container_width=True,
            hide_index=True,
        )

    st.caption(
        "Metrics summarize the loaded report, not live network traffic. "
        "A predicted attack is a model output, not proof of malicious activity."
    )

# --------------------------------------------------
# Incident Explorer
# --------------------------------------------------
elif page == "Incident Explorer":
    st.subheader("Incident Explorer")

    risk_options = sorted(incidents["RiskLevel"].unique().tolist())
    selected_risks = st.multiselect(
        "Filter by risk level",
        risk_options,
        default=risk_options,
    )

    prediction_filter = st.selectbox(
        "Prediction",
        ["All", "Attack", "Normal"],
    )

    filtered = incidents[
        incidents["RiskLevel"].isin(selected_risks)
    ].copy()

    if prediction_filter == "Attack":
        filtered = filtered[filtered["PredictedClass"] == 1]
    elif prediction_filter == "Normal":
        filtered = filtered[filtered["PredictedClass"] == 0]

    search_text = st.text_input(
        "Search record, action, or response mode"
    ).strip().lower()

    if search_text:
        searchable = [
            column for column in [
                "RecordIndex",
                "RecommendedAction",
                "ResponseMode",
                "RiskLevel",
            ]
            if column in filtered.columns
        ]
        if searchable:
            mask = filtered[searchable].astype(str).apply(
                lambda column: column.str.lower().str.contains(
                    search_text, regex=False
                )
            ).any(axis=1)
            filtered = filtered[mask]

    st.write(f"Showing **{len(filtered):,}** incidents.")

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Download filtered incidents as CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="filtered_iot_incidents.csv",
        mime="text/csv",
    )

# --------------------------------------------------
# Explainability
# --------------------------------------------------
elif page == "Explainability":
    st.subheader("Model Explainability with SHAP")

    if not integrated.empty:
        st.write("Integrated incident explanations")

        explanation_columns = [
            column for column in [
                "RecordIndex",
                "PredictedClass",
                "AttackProbability",
                "RiskScore",
                "RiskLevel",
                "TopPositiveSHAP",
                "TopNegativeSHAP",
                "RecommendedAction",
            ]
            if column in integrated.columns
        ]

        if explanation_columns:
            st.dataframe(
                integrated[explanation_columns],
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.info("The integrated SHAP incident report was not found.")

    if not shap_data.empty:
        st.divider()
        st.subheader("Feature Contributions")

        if "AbsoluteSHAP" in shap_data.columns:
            shap_data["AbsoluteSHAP"] = pd.to_numeric(
                shap_data["AbsoluteSHAP"], errors="coerce"
            )
            shap_data = shap_data.dropna(subset=["AbsoluteSHAP"])

            if "Feature" in shap_data.columns:
                top_features = (
                    shap_data.groupby("Feature")["AbsoluteSHAP"]
                    .mean()
                    .sort_values(ascending=False)
                    .head(15)
                )
                st.bar_chart(top_features)

        st.caption(
            "Absolute SHAP values indicate contribution magnitude. "
            "They do not, by themselves, indicate whether a feature "
            "increases or decreases attack probability."
        )
    else:
        st.info("The standalone SHAP explanation report was not found.")

    st.caption(
        "These explanations come from previously generated reports. "
        "They are not generated live by this dashboard."
    )

# --------------------------------------------------
# Project Information
# --------------------------------------------------
elif page == "Project Information":
    st.subheader("About This Project")

    st.markdown(
        """
        **Project:** An Explainable and Risk-Aware Intrusion Detection
        and Automated Incident Response Framework for IoT Networks.

        **Dataset:** CICIoT2023.

        **Machine learning:** Random Forest binary classification.

        **Explainability:** SHAP feature contributions.

        **Risk assessment:** Low, Medium, High, and Critical categories
        as recorded by the existing incident-response engine.

        **Current dashboard mode:** Reads previously generated CSV reports.
        It does not capture network traffic or execute containment actions.
        """
    )

    st.subheader("Available Project Files")

    for path in [
        PROJECT_DIR / "models" / "random_forest_capture_based.joblib",
        INCIDENT_REPORT,
        INTEGRATED_REPORT,
        SHAP_REPORT,
    ]:
        status = "Available" if path.exists() else "Not found"
        st.write(f"- `{path.relative_to(PROJECT_DIR)}` — {status}")

    st.warning(
        "This dashboard is an analysis interface. No real network "
        "blocking or automated containment is performed."
    )

# --------------------------------------------------
# Live CSV Prediction
# --------------------------------------------------
elif page == "Live Prediction":
    st.subheader("Live IoT Traffic Prediction")
    st.write(
        "Upload a CSV containing IoT traffic features to classify "
        "records using the saved Random Forest model."
    )

    @st.cache_resource
    def load_saved_model():
        model_path = (
            PROJECT_DIR
            / "models"
            / "random_forest_capture_based.joblib"
        )
        saved = joblib.load(model_path)
        return saved["model"], saved["feature_names"]

    try:
        model, feature_names = load_saved_model()
    except Exception as exc:
        st.error(f"Could not load the saved model: {exc}")
        st.stop()

    uploaded_file = st.file_uploader(
        "Upload an IoT traffic CSV",
        type=["csv"],
        help="The CSV must contain all 36 features expected by the model.",
    )

    if uploaded_file is not None:
        try:
            uploaded_data = pd.read_csv(uploaded_file)

            st.write("Uploaded data preview")
            st.dataframe(
                uploaded_data.head(10),
                use_container_width=True,
                hide_index=True,
            )

            missing_features = [
                name for name in feature_names
                if name not in uploaded_data.columns
            ]

            if missing_features:
                st.error(
                    "The CSV is missing required features: "
                    + ", ".join(missing_features)
                )
                st.stop()

            # Select features in the exact training order.
            features = uploaded_data[feature_names].copy()

            # Convert feature values to numeric values.
            for column in feature_names:
                features[column] = pd.to_numeric(
                    features[column], errors="coerce"
                )

            features = features.replace(
                [float("inf"), float("-inf")], float("nan")
            )

            invalid_rows = features.isna().any(axis=1)

            if invalid_rows.any():
                st.error(
                    f"{int(invalid_rows.sum())} row(s) contain missing, "
                    "infinite, or non-numeric feature values. "
                    "Please clean the CSV and upload it again."
                )
                st.stop()

            if st.button("Run Intrusion Detection", type="primary"):
                predictions = model.predict(features)
                probabilities = model.predict_proba(features)

                classes = list(model.classes_)
                attack_class_index = classes.index(1)

                attack_probabilities = probabilities[
                    :, attack_class_index
                ]

                results = uploaded_data.copy()
                results["PredictedClass"] = predictions
                results["Prediction"] = [
                    "ATTACK" if value == 1 else "NORMAL"
                    for value in predictions
                ]
                results["AttackProbability"] = attack_probabilities
                results["RiskScore"] = attack_probabilities * 100

                results["RiskLevel"] = pd.cut(
                    results["RiskScore"],
                    bins=[-0.001, 25, 50, 75, 100.001],
                    labels=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    include_lowest=True,
                ).astype(str)

                attack_count = int((predictions == 1).sum())
                normal_count = int((predictions == 0).sum())

                col1, col2, col3 = st.columns(3)
                col1.metric("Records Analyzed", f"{len(results):,}")
                col2.metric("Predicted Attacks", f"{attack_count:,}")
                col3.metric("Predicted Normal", f"{normal_count:,}")

                st.subheader("Prediction Results")
                st.dataframe(
                    results,
                    use_container_width=True,
                    hide_index=True,
                )

                st.subheader("Risk Distribution")
                st.bar_chart(results["RiskLevel"].value_counts())

                st.download_button(
                    "Download Prediction Results",
                    data=results.to_csv(index=False).encode("utf-8"),
                    file_name="iot_prediction_results.csv",
                    mime="text/csv",
                )

                st.warning(
                    "These are model predictions on uploaded data, "
                    "not live network monitoring. Risk levels are "
                    "probability-based indicators, not verified incident "
                    "severity. No firewall or containment action is executed."
                )

        except Exception as exc:
            st.error(f"Could not process the uploaded CSV: {exc}")
