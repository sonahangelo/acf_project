import os
import sqlite3
import pytest
import app as app_module


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    # Ensure database path directory exists before running test requests
    db_path = app_module.cfg.get("db_path", "data/acf.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
        
    with app_module.app.test_client() as client:
        yield client


def test_summary_endpoint_returns_json(client):
    response = client.get("/api/summary", headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="})
    assert response.status_code == 200


def test_alerts_endpoint_returns_list(client):
    response = client.get("/api/alerts", headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="})
    assert response.status_code == 200


def test_blocklist_endpoint_returns_list(client):
    response = client.get("/api/blocklist", headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="})
    assert response.status_code == 200


def test_traffic_timeline_endpoint_returns_list(client):
    response = client.get("/api/traffic-timeline", headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="})
    assert response.status_code == 200


def test_mark_feedback_endpoint_sets_label(client):
    db_path = app_module.cfg.get("db_path", "data/acf.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO alerts (src_ip, dst_ip, action, score) VALUES (?, ?, ?, ?)",
        ("9.9.9.9", "1.1.1.1", "BLOCK", -0.1),
    )
    conn.commit()
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    response = client.post(
        f"/api/alerts/{alert_id}/feedback",
        json={"label": "false_positive"},
        headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="},
    )
    assert response.status_code == 200


def test_mark_feedback_on_nonexistent_alert_returns_404(client):
    response = client.post(
        "/api/alerts/9999/feedback",
        json={"label": "false_positive"},
        headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="},
    )
    assert response.status_code == 404
