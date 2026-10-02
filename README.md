
# AI-Powered Cybersecurity Threat Detection System

An educational, dataset-driven machine-learning project that classifies synthetic network-event records as **Benign** or **Potential Threat** and presents results in a SOC-style Streamlit dashboard.

> **Safety and scope:** This repository uses synthetic records by default. It does not capture live packets, connect to corporate security systems, block traffic, or prove that an event is malicious. Model results are demonstrations, not validated production detection performance.

## Features

- Reproducible synthetic training-data generation
- Random Forest classifier using scikit-learn
- Held-out test split and accuracy, precision, recall, F1, and classification report
- Simulated event feed and interactive charts
- CSV export of analyzed events
- Optional CSV upload for records with the expected numeric feature columns
- Automated tests with pytest

## Technology

Python, pandas, NumPy, scikit-learn, Streamlit, Plotly, pytest.

## Quick start (Windows)

1. Install Python 3.11 or 3.12 and Git.
2. Open PowerShell in this project folder.
3. Create a virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

4. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. Run tests:

   ```powershell
   python -m pytest -q
   ```

6. Start the dashboard:

   ```powershell
   python -m streamlit run app.py
   ```

7. Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## Input CSV schema

The uploaded CSV must contain numeric columns named exactly:

- `duration_seconds`
- `bytes_sent`
- `bytes_received`
- `failed_connections`
- `unique_destination_ports`
- `connection_rate`
- `packet_size_mean`

Extra columns are retained. The model predicts from the seven listed features. The uploaded data should not contain secrets or personal data.

## Dataset and evaluation notes

The built-in data is synthetic and intentionally simplified to make the full workflow runnable without downloading a dataset. The displayed test metrics only measure performance on a held-out portion of this synthetic data. They are not a benchmark for enterprise traffic.

For a stronger research version, replace or supplement the synthetic data with a public intrusion-detection dataset such as CIC-IDS2017 or UNSW-NB15. Review the dataset's license and terms, document the exact version and selected features, remove identifiers that can leak labels, check class imbalance, split by time or host where appropriate, and evaluate false-positive rates. Never claim a model detects a threat family unless your labels and experiments support that claim.

## Suggested project structure


AI-Powered-Cybersecurity-Threat-Detection-System/
├── app.py
├── src/
│   ├── __init__.py
│   ├── data_simulator.py
│   └── detector.py
├── tests/
│   └── test_detector.py
├── requirements.txt
├── .gitignore
└── README.md


## Limitations and future improvements

- Add a public dataset ingestion and cleaning pipeline.
- Compare Logistic Regression, Random Forest, and Gradient Boosting.
- Add a confusion matrix and precision-recall curve.
- Track model/data versions and experiment parameters.
- Add a rule-based baseline and compare it with ML.
- Add alert severity as an analyst triage aid, not as proof of compromise.
- Add CI with GitHub Actions.
- Deploy the Streamlit app using a compatible hosting service.

## Ethical use

Use this application for defensive learning, synthetic simulation, and authorized datasets. Do not upload confidential logs or use outputs to take disruptive actions without human review.

# AI-Powered-Cybersecurity-Threat-Detection-System
Machine-learning-based cybersecurity threat detection using synthetic network events, model evaluation, and an interactive Streamlit SOC dashboard.

