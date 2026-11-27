\# IoT Sentinel



\### Explainable and Risk-Aware Intrusion Detection and Automated Incident Response for IoT Networks



IoT Sentinel is an academic cybersecurity prototype that integrates machine learning-based intrusion detection, explainable artificial intelligence, device-context-aware risk assessment, incident management and simulation-based incident response into a unified security monitoring platform.



\## 1. Project Overview



Traditional intrusion detection systems primarily identify malicious network traffic. IoT Sentinel extends this approach by incorporating device criticality, network exposure, attack impact, probability calibration and explainable machine learning into the security investigation workflow.



The framework provides security analysts with attack predictions, contextual risk scores, feature-level explanations, incident records and policy-based response recommendations.



\## 2. Project Objectives



\- Detect malicious traffic in IoT networks.

\- Classify traffic into multiple attack families.

\- Explain machine learning predictions using SHAP.

\- Estimate contextual risk using device and attack characteristics.

\- Prioritize security incidents based on severity.

\- Generate policy-based incident response recommendations.

\- Maintain persistent incident and response audit histories.

\- Provide an interactive security monitoring dashboard.



\## 3. System Architecture



```mermaid

flowchart TD

&#x20;   A\[IoT Network Traffic Dataset] --> B\[Data Collection and CSV Replay]

&#x20;   B --> C\[Data Preprocessing]

&#x20;   C --> D\[36 Input Features]

&#x20;   D --> E\[Random Forest Classifier]

&#x20;   E --> F\[Attack Family Classification]

&#x20;   E --> G\[Binary Probability Calibration]

&#x20;   E --> H\[SHAP Explainability]

&#x20;   F --> I\[Context-Aware Risk Assessment]

&#x20;   G --> I

&#x20;   J\[Device Context Profiles] --> I

&#x20;   K\[Attack Impact Policy] --> I

&#x20;   I --> L\[Incident Management]

&#x20;   I --> M\[Response Policy Engine]

&#x20;   M --> N\[Simulated Response Recommendations]

&#x20;   L --> O\[PostgreSQL Database]

&#x20;   N --> O

&#x20;   O --> P\[Angular Security Dashboard]

&#x20;   H --> P

```



\## 4. Application Modules



| Module | Functionality |

|---|---|

| Security Dashboard | Security statistics, incident summaries and monitoring records |

| Intrusion Detection | Multiclass prediction, risk assessment and context comparison |

| Live Traffic Monitor | Controlled CSV-based traffic replay and persistent security monitoring |

| Incident Management | Incident investigation, status transitions and audit history |

| IoT Device Management | Device registration and demonstration context profiles |

| Explainable AI | SHAP-based family and binary attack explanations |

| Incident Response Center | Response planning, policy checks and safety restrictions |

| Reports and Batch Analysis | CSV analysis, batch predictions and report exports |

| AI Security Assistant | Rule-based security guidance and current incident statistics |



\## 5. Technology Stack



| Layer | Technologies |

|---|---|

| Programming | Python, TypeScript |

| Machine Learning | Scikit-learn, Random Forest, XGBoost |

| Data Processing | Pandas, NumPy |

| Explainable AI | SHAP |

| Backend | FastAPI, Uvicorn |

| Frontend | Angular 21, RxJS, SCSS |

| Database | PostgreSQL, Supabase |

| Database Connectivity | SQLAlchemy, Psycopg |

| Visualization | Matplotlib, Chart.js |

| Version Control | Git, GitHub |



\## 6. Dataset



The project uses the CICIoT2023 dataset for IoT network intrusion detection.



The multiclass model supports the following eight traffic families:



| Class ID | Traffic Family |

|---:|---|

| 0 | Benign |

| 1 | DDoS |

| 2 | DoS |

| 3 | Reconnaissance |

| 4 | BruteForce |

| 5 | Spoofing |

| 6 | Mirai |

| 7 | WebBased |



The model uses 36 numerical network traffic features.



Dataset preparation includes capture-based partitioning, numerical validation, sampling and duplicate filtering.



\### Verified Dataset Distribution



| Partition | Records |

|---|---:|

| Training | 872,867 |

| Validation | 182,398 |

| Held-out testing | 188,343 |



BruteForce has no held-out test samples and therefore cannot be independently evaluated using the current test partition.



\## 7. Machine Learning Pipeline



The machine learning pipeline consists of:



1\. Dataset inventory and attack-family mapping.

2\. Capture-based dataset partitioning.

3\. Feature preprocessing and numerical validation.

4\. Duplicate filtering and dataset verification.

5\. Random Forest and XGBoost training.

6\. Validation-based model selection.

7\. Binary attack probability calibration.

8\. Held-out model evaluation.

9\. Backend inference integration.



\### Deployed Model



\- Algorithm: Random Forest

\- Model version: multiclass\_rf\_v3\_calibrated

\- Input features: 36

\- Output classes: 8

\- Calibration scope: Binary attack probability

\- High-confidence alert threshold: 0.90



Individual attack-family probabilities are not calibrated.



\## 8. Context-Aware Risk Assessment



The framework calculates a contextual risk score using:



\*\*Risk Score = 100 × P × (0.40C + 0.40I + 0.20E)\*\*



Where:



\- P represents calibrated attack probability.

\- C represents device criticality.

\- I represents expected attack impact.

\- E represents device exposure.



\### Risk Classification



| Risk Score | Severity |

|---|---|

| 0 to below 25 | Low |

| 25 to below 50 | Medium |

| 50 to below 75 | High |

| 75 to 100 | Critical |



The weights and severity boundaries are provisional academic policy parameters rather than independently validated operational risk estimates.



\## 9. Explainable Artificial Intelligence



IoT Sentinel uses SHAP TreeExplainer to provide feature-level explanations for:



\- Predicted attack-family probability.

\- Raw binary attack probability.

\- Positive and negative feature contributions.

\- Feature importance rankings.

\- Prediction reconstruction and additivity verification.



SHAP explanations describe model behavior and should not be interpreted as causal evidence.



\## 10. Incident Management and Response



The incident management module supports the following lifecycle:



```mermaid

flowchart LR

&#x20;   A\[Open] --> B\[Acknowledged]

&#x20;   B --> C\[Investigating]

&#x20;   C --> D\[Resolved]

&#x20;   C --> E\[False Positive]

```



Incident status updates and audit events are stored transactionally in PostgreSQL.



The response policy engine evaluates attack probability, family confidence, contextual risk, device verification and containment restrictions.



Response recommendations may include simulated rate limiting, device isolation or traffic filtering.



Real network containment is disabled. Persistent approval, execution and rollback are not enabled in the current prototype.



\## 11. Experimental Results



\### Held-Out Multiclass Evaluation



| Metric | Result |

|---|---:|

| Test records | 188,343 |

| Accuracy | 84.69% |

| Balanced accuracy | 70.28% |

| Macro F1-score, supported classes | 69.69% |

| Weighted F1-score | 85.61% |

| Binary ROC-AUC | 0.982837 |



\### Per-Family Performance



| Attack Family | Precision | Recall | F1-score |

|---|---:|---:|---:|

| Benign | 56.12% | 57.88% | 56.98% |

| DDoS | 95.33% | 82.36% | 88.37% |

| DoS | 53.78% | 82.90% | 65.24% |

| Reconnaissance | 56.24% | 56.43% | 56.34% |

| BruteForce | N/A | N/A | N/A |

| Spoofing | 88.57% | 73.76% | 80.49% |

| Mirai | 98.17% | 99.83% | 98.99% |

| WebBased | 44.42% | 38.76% | 41.40% |



\### High-Confidence Alert Performance



At the fixed calibrated attack probability threshold of 0.90:



| Metric | Result |

|---|---:|

| Accuracy | 96.39% |

| Precision | 99.39% |

| Attack recall | 96.89% |

| False positive rate | 21.90% |

| False negative rate | 3.11% |

| True positives | 177,656 |

| True negatives | 3,894 |

| False positives | 1,092 |

| False negatives | 5,701 |



\### Probability Calibration



| Metric | Raw | Calibrated |

|---|---:|---:|

| ROC-AUC | 0.982837 | 0.982837 |

| Brier score | 0.015205 | 0.015524 |

| Binary log loss | 0.052920 | 0.051457 |

| Expected calibration error | 0.007038 | 0.008060 |



Calibration improved binary log loss but worsened Brier score and expected calibration error on the held-out dataset.



\### Local Model Performance



| Metric | Result |

|---|---:|

| Batch inference throughput | 209,922 records/sec |

| Mean single-record inference latency | 30.43 ms |

| P95 single-record inference latency | 41.76 ms |



These measurements represent local model inference on the development machine and do not represent end-to-end system throughput.



\## 12. Research Visualizations



\### Multiclass Confusion Matrix



!\[Confusion Matrix](results/multiclass/final\_evaluation/graphs/01\_confusion\_matrix.png)



\### Attack-Family Classification Performance



!\[Per-Family Performance](results/multiclass/final\_evaluation/graphs/03\_per\_family\_performance.png)



\### Binary ROC Curve



!\[ROC Curve](results/multiclass/final\_evaluation/graphs/04\_roc\_curve.png)



\### Probability Calibration



!\[Calibration Curve](results/multiclass/final\_evaluation/graphs/06\_calibration\_curve.png)



Additional research graphs and aggregate evaluation metrics are available in:



`results/multiclass/final\_evaluation/`



\## 13. Project Structure



```text

IoT-Intrusion-Detection/

├── backend/

│   ├── app/

│   └── requirements.txt

├── frontend/

│   ├── public/

│   ├── src/

│   ├── angular.json

│   └── package.json

├── database/

│   └── migrations/

├── models/

├── notebooks/

├── results/

│   └── multiclass/

├── src/

├── requirements.txt

├── .gitignore

└── README.md

```



Local datasets, virtual environments, environment credentials and backups are excluded from normal Git tracking.



\## 14. Installation and Setup



\### Prerequisites



\- Python 3.14, as used in the development environment

\- Node.js compatible with Angular 21

\- npm

\- PostgreSQL or Supabase database

\- Git



\### Clone the Repository



```bash

git clone https://github.com/21691A3708/IoT-Intrusion-Detection.git

cd IoT-Intrusion-Detection

```



\### Python Environment



On Windows PowerShell:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1



python -m pip install -r requirements.txt

python -m pip install -r backend/requirements.txt

```



The dependency manifests must be checked against the final development environment before claiming clean-install reproducibility.



\### Database Configuration



Create a local `backend/.env` file containing the following variables:



```env

DB\_HOST=your\_database\_host

DB\_PORT=5432

DB\_NAME=postgres

DB\_USER=your\_database\_user

DB\_PASSWORD=your\_database\_password

```



Never commit actual database credentials.



The existing database requires the base application schema, including its device registry and Supabase authentication references, before applying the multiclass migrations.



Apply the following migrations in order to a correctly configured database:



```text

database/migrations/001\_multiclass\_schema.sql

database/migrations/002\_multiclass\_incident\_audit.sql

```



\### Start the Backend



```powershell

cd backend



python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

```



Backend URL:



http://127.0.0.1:8000



Interactive API documentation:



http://127.0.0.1:8000/docs



\### Start the Frontend



Open another terminal from the project root:



```powershell

cd frontend



npm ci



npm start

```



Frontend URL:



http://localhost:4200



\## 15. Principal API Endpoints



| Method | Endpoint | Purpose |

|---|---|---|

| GET | /api/multiclass/model-info | Model information |

| POST | /api/multiclass/predict | Single traffic prediction |

| POST | /api/multiclass/predict-batch | Batch prediction |

| POST | /api/multiclass/explain | SHAP explanation |

| GET | /api/multiclass/device-profiles | Device context profiles |

| POST | /api/multiclass/assess-risk | Context-aware risk assessment |

| POST | /api/multiclass/compare-contexts | Device context comparison |

| POST | /api/multiclass/plan-response | Response planning |

| GET | /api/multiclass/incidents | Incident listing |

| GET | /api/multiclass/incidents/summary | Incident statistics |

| PATCH | /api/multiclass/incidents/{incident\_id}/status | Incident status update |

| GET | /api/multiclass/incidents/{incident\_id}/audit | Incident audit history |

| GET | /api/persistent-responses | Persistent response history |

| POST | /api/persistent-responses | Persistent traffic assessment |

| GET | /api/persistent-responses/{response\_id}/audit | Response audit history |



\## 16. Testing and Verification



The development verification process includes:



| Verification | Result |

|---|---|

| Functional browser modules | 9/9 before frontend optimization |

| System integration audit | 38/38 |

| Context comparison regression | 42/42 assessments |

| Invalid context comparison requests | 4/4 rejected |

| Database snapshot integrity | 31/31 |

| Research graphs | 10/10 generated |

| TypeScript compilation | Passed |

| Angular compilation | Passed |

| Production build | Passed with budget warnings |



\### Run Verification Scripts



With the backend running and the required local datasets available:



```powershell

python test\_context\_comparison\_api.py



python test\_final\_database\_integrity.py



python test\_stage\_5\_batch.py



python src/final\_integration\_audit.py

```



\### Reproduce Final Evaluation



```powershell

python src/evaluate\_final\_multiclass\_model.py

```



The trained model and verified held-out test dataset must be available locally.



\## 17. Frontend Optimization



Six application components use Angular deferred loading.



| Measurement | Before | After |

|---|---:|---:|

| Initial bundle size | 763.12 kB | 616.60 kB |

| Estimated transfer size | 187.34 kB | 167.42 kB |



Initial bundle size reduction: approximately 19.20%.



Remaining build budget warnings and post-optimization browser verification are documented limitations.



\## 18. Security and Research Limitations



\- This project is an academic prototype, not a production intrusion prevention system.

\- Traffic monitoring uses controlled dataset replay rather than live packet capture.

\- Device context profiles are demonstration profiles and device identities are not independently verified.

\- Analyst authentication and authorization are not implemented for the multiclass workflow.

\- Real network containment is disabled.

\- The security assistant uses rule-based responses rather than a generative language model.

\- The test dataset is highly imbalanced toward attack traffic.

\- BruteForce lacks held-out test support.

\- The held-out benign false positive rate remains significant.

\- Duplicate filtering may affect the evaluation results.

\- Capture-based separation does not guarantee independent network sessions.

\- Contextual risk and response effectiveness require additional independent experiments.



\## 19. Future Enhancements



\- Live network traffic acquisition.

\- Authenticated analyst access and role-based authorization.

\- Verified device identity management.

\- Improved minority attack-family detection.

\- Independent risk assessment validation.

\- SHAP stability and explanation fidelity experiments.

\- Controlled response effectiveness evaluation.

\- End-to-end latency and resource utilization benchmarking.

\- Evaluation on additional IoT network datasets.



\## 20. Dataset Reference



Neto, E. C. P., et al. (2023). CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment. Sensors, 23(13), 5941.



DOI: https://doi.org/10.3390/s23135941



\## 21. Project Status



Functional academic prototype implemented.



Final research validation, deployment hardening and reproducibility verification remain ongoing.



\---



\*\*IoT Sentinel — Explainable, Context-Aware and Risk-Aware IoT Security Monitoring.\*\*
