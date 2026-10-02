import pandas as pd
import pytest
from src.data_simulator import generate_labeled_dataset, generate_live_events
from src.detector import train_detector, evaluate_detector, predict_events, FEATURE_COLUMNS

def test_generated_dataset_has_expected_columns_and_labels():
    data = generate_labeled_dataset(n=200, seed=7)
    assert set(FEATURE_COLUMNS + ["label"]).issubset(data.columns)
    assert set(data["label"].unique()) == {0, 1}

def test_model_trains_and_evaluates():
    data = generate_labeled_dataset(n=300, seed=8)
    model, X_test, y_test = train_detector(data)
    metrics = evaluate_detector(model, X_test, y_test)
    assert 0 <= metrics["accuracy"] <= 1
    assert 0 <= metrics["precision"] <= 1
    assert "Potential Threat" in metrics["classification_report"]

def test_predictions_include_labels_and_probability():
    data = generate_labeled_dataset(n=300, seed=9)
    model, _, _ = train_detector(data)
    events = generate_live_events(n=12, seed=10)
    results = predict_events(model, events)
    assert len(results) == 12
    assert "prediction" in results.columns
    assert "threat_probability" in results.columns

def test_missing_feature_raises_clear_error():
    data = generate_labeled_dataset(n=200)
    model, _, _ = train_detector(data)
    with pytest.raises(ValueError, match="missing required columns"):
        predict_events(model, pd.DataFrame({"bytes_sent": [10]}))
