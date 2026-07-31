import hashlib
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ai_model import AnomalyModel


def test_model_hash_mismatch_fails_before_joblib_load(tmp_path):
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"not a pickle")

    model = AnomalyModel(model_path=str(model_path), expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="Model hash mismatch"):
        model.load()


def test_model_hash_accepts_matching_digest_before_deserialization(tmp_path):
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"not a pickle")
    digest = hashlib.sha256(b"not a pickle").hexdigest()

    model = AnomalyModel(model_path=str(model_path), expected_sha256=digest)
    with pytest.raises(Exception):
        model.load()
