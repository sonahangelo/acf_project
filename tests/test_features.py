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


def test_all_model_feature_columns_exist_in_db_schema():
    """
    Regression test: every column ai_model.py trains on must also exist
    in the SQLite traffic table (db.py's TRAFFIC_COLUMNS), or training
    fails with a KeyError once real data is queried back out. This bit
    us once already when icmp_count was added to one list but not the
    other.
    """
    from db import TRAFFIC_COLUMNS
    missing = [col for col in MODEL_FEATURE_COLUMNS if col not in TRAFFIC_COLUMNS]
    assert missing == [], f"Columns in MODEL_FEATURE_COLUMNS but missing from TRAFFIC_COLUMNS: {missing}"


def test_traffic_columns_match_actual_db_schema():
    """
    Regression test: TRAFFIC_COLUMNS (the Python list) must match the
    REAL columns in a freshly created SQLite table. This is different
    from the MODEL_FEATURE_COLUMNS check above -- that one only catches
    Python-list drift, not the case where TRAFFIC_COLUMNS itself was
    updated but an already-deployed database's table wasn't recreated
    to match (bit us with icmp_count, then again with ttl).
    """
    import sqlite3
    from db import TRAFFIC_COLUMNS, init_db

    conn = sqlite3.connect(":memory:")
    init_db(conn)
    actual_columns = {row[1] for row in conn.execute("PRAGMA table_info(traffic)").fetchall()}

    missing = [col for col in TRAFFIC_COLUMNS if col not in actual_columns]
    assert missing == [], f"TRAFFIC_COLUMNS lists columns not actually in the traffic table: {missing}"
