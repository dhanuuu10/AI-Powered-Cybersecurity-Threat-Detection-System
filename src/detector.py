"""Training and evaluation helpers for the educational threat detector."""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

FEATURE_COLUMNS = [
    "duration_seconds",
    "bytes_sent",
    "bytes_received",
    "failed_connections",
    "unique_destination_ports",
    "connection_rate",
    "packet_size_mean",
]

def train_detector(data: pd.DataFrame):
    missing = [col for col in FEATURE_COLUMNS + ["label"] if col not in data.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")
    X = data[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    y = pd.to_numeric(data["label"], errors="raise").astype(int)
    if set(y.unique()) - {0, 1}:
        raise ValueError("Labels must be 0 (benign) or 1 (potential threat).")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=150, random_state=42, class_weight="balanced", n_jobs=-1
        )),
    ])
    model.fit(X_train, y_train)
    return model, X_test, y_test

def evaluate_detector(model, X_test, y_test):
    predictions = model.predict(X_test)
    return {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions, zero_division=0),
        "recall": recall_score(y_test, predictions, zero_division=0),
        "f1": f1_score(y_test, predictions, zero_division=0),
        "classification_report": classification_report(
            y_test, predictions, target_names=["Benign", "Potential Threat"], zero_division=0
        ),
    }

def predict_events(model, events: pd.DataFrame):
    missing = [col for col in FEATURE_COLUMNS if col not in events.columns]
    if missing:
        raise ValueError(f"Events are missing required columns: {', '.join(missing)}")
    result = events.copy()
    X = result[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    predictions = model.predict(X)
    result["prediction"] = ["Potential Threat" if p == 1 else "Benign" for p in predictions]
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)
        result["threat_probability"] = probabilities[:, 1].round(4)
    return result
