import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features import to_model_vector, MODEL_FEATURE_COLUMNS


def test_to_model_vector_length_matches_columns():
    feats = {col: 1 for col in MODEL_FEATURE_COLUMNS}
    vector = to_model_vector(feats)
    assert len(vector) == len(MODEL_FEATURE_COLUMNS)


def test_to_model_vector_fills_missing_with_zero():
    feats = {}  # nothing set
    vector = to_model_vector(feats)
    assert all(v == 0 for v in vector)


def test_to_model_vector_handles_none_values():
    feats = {col: None for col in MODEL_FEATURE_COLUMNS}
    vector = to_model_vector(feats)
    assert all(v == 0 for v in vector)
