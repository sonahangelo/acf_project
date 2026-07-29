import pytest
import pandas as pd
import ai_model

def test_explain_manual():
    # Dynamically pick the model class defined in ai_model
    ModelClass = getattr(ai_model, 'ACFModel', None) or getattr(ai_model, 'AnomalyModel', None)
    
    model = ModelClass()
    model.load()

    # 14 features matching MODEL_FEATURE_COLUMNS
    fake_scan_vector = [60, 44444, 80, 0.01, 1, 60, 100.0, 6000.0, 50, 500.0, 1, 0, 0, 0]

    label, score = model.predict(fake_scan_vector)
    assert label in [0, 1]
