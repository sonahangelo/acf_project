import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from utils import validate_config


def _valid_cfg(**overrides):
    base = {
        "interface": "", "bpf_filter": "ip", "contamination": 0.02,
        "dry_run": True, "whitelist": ["127.0.0.1"],
        "db_path": "data/acf.db", "model_path": "models/anomaly_model.pkl",
    }
    base.update(overrides)
    return base


def test_valid_config_passes_without_error():
    validate_config(_valid_cfg())  # should not raise / exit


def test_missing_required_key_is_caught(capsys):
    cfg = _valid_cfg()
    del cfg["dry_run"]
    with pytest.raises(SystemExit):
        validate_config(cfg)
    assert "dry_run" in capsys.readouterr().err


def test_wrong_type_whitelist_is_caught(capsys):
    cfg = _valid_cfg(whitelist="127.0.0.1")  # string instead of list
    with pytest.raises(SystemExit):
        validate_config(cfg)
    assert "whitelist" in capsys.readouterr().err


def test_contamination_out_of_range_is_caught(capsys):
    cfg = _valid_cfg(contamination=1.5)
    with pytest.raises(SystemExit):
        validate_config(cfg)
    assert "contamination" in capsys.readouterr().err


def test_negative_threshold_is_caught(capsys):
    cfg = _valid_cfg(syn_flood_threshold=-5)
    with pytest.raises(SystemExit):
        validate_config(cfg)
    assert "syn_flood_threshold" in capsys.readouterr().err


def test_non_string_whitelist_entry_is_caught(capsys):
    cfg = _valid_cfg(whitelist=["127.0.0.1", 42])
    with pytest.raises(SystemExit):
        validate_config(cfg)
    assert "whitelist[1]" in capsys.readouterr().err
