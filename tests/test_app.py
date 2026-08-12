import os
import sqlite3
import pytest
import app as app_module
from db import init_db


def auth_headers():
    return {
        "Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM=",
        "X-ACF-CSRF-Token": app_module.CSRF_TOKEN,
    }


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    db_path = app_module.cfg.get("db_path", "data/acf.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    init_db(conn)
    conn.close()

    with app_module.app.test_client() as client:
        yield client


def test_summary_endpoint_returns_json(client):
    response = client.get("/api/summary", headers=auth_headers())
    assert response.status_code == 200


def test_alerts_endpoint_returns_list(client):
    response = client.get("/api/alerts", headers=auth_headers())
    assert response.status_code == 200


def test_blocklist_endpoint_returns_list(client):
    response = client.get("/api/blocklist", headers=auth_headers())
    assert response.status_code == 200


def test_traffic_timeline_endpoint_returns_list(client):
    response = client.get("/api/traffic-timeline", headers=auth_headers())
    assert response.status_code == 200


def test_mark_feedback_endpoint_sets_label(client):
    db_path = app_module.cfg.get("db_path", "data/acf.db")
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
        headers=auth_headers(),
    )
    assert response.status_code == 200


def test_mark_feedback_on_nonexistent_alert_returns_404(client):
    response = client.post(
        "/api/alerts/9999/feedback",
        json={"label": "false_positive"},
        headers=auth_headers(),
    )
    assert response.status_code == 404


def test_alerts_rejects_invalid_limit(client):
    response = client.get("/api/alerts?limit=abc", headers=auth_headers())
    assert response.status_code == 400


def test_feedback_requires_csrf_token(client):
    response = client.post(
        "/api/alerts/1/feedback",
        json={"label": "false_positive"},
        headers={"Authorization": "Basic YWRtaW46YWNmcGFzc3dvcmQxMjM="},
    )
    assert response.status_code == 403


def test_unblock_rejects_invalid_ip(client):
    response = client.post(
        "/api/blocklist/not-an-ip/unblock",
        headers=auth_headers(),
    )
    assert response.status_code == 400


def test_investigate_endpoint_returns_ip_context(client):
    db_path = app_module.cfg.get("db_path", "data/acf.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO alerts (timestamp, src_ip, dst_ip, action, score, rule_reason, severity, mitre_technique, mitre_tactic) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (123.0, "8.8.8.8", "1.1.1.1", "BLOCK", -0.2, "brute_force test", "high", "T1110", "Credential Access"),
    )
    conn.execute(
        "INSERT INTO traffic (timestamp, src_ip, dst_ip, packet_length) VALUES (?, ?, ?, ?)",
        (122.0, "8.8.8.8", "1.1.1.1", 100),
    )
    conn.commit()
    conn.close()

    response = client.get("/api/investigate/8.8.8.8", headers=auth_headers())
    assert response.status_code == 200
    data = response.get_json()
    assert data["ip"] == "8.8.8.8"
    assert data["alerts"]
    assert data["timeline"]


def test_report_endpoint_returns_html(client):
    response = client.get("/api/report", headers=auth_headers())
    assert response.status_code == 200
    assert b"ACF Security Report" in response.data
    assert b"Generated at Unix time" not in response.data
    assert b"MITRE ATT&CK Summary" in response.data


def test_report_endpoint_supports_range_filter(client):
    response = client.get("/api/report?range=24h", headers=auth_headers())
    assert response.status_code == 200
    assert b"Scope: Last 24 hours" in response.data


def test_report_endpoint_rejects_bad_range(client):
    response = client.get("/api/report?range=forever", headers=auth_headers())
    assert response.status_code == 400
