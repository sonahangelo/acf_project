import pytest
import sqlite3
import base64
import app as app_module

@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    with app_module.app.test_client() as client:
        # Generate basic auth header for admin:acfpassword123
        auth_bytes = base64.b64encode(b"admin:acfpassword123").decode("utf-8")
        client.environ_base['HTTP_AUTHORIZATION'] = f'Basic {auth_bytes}'
        yield client

def test_index_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200

def test_summary_endpoint_returns_json(client):
    response = client.get("/api/summary")
    assert response.status_code == 200

def test_alerts_endpoint_returns_list(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200

def test_blocklist_endpoint_returns_list(client):
    response = client.get("/api/blocklist")
    assert response.status_code == 200

def test_traffic_timeline_endpoint_returns_list(client):
    response = client.get("/api/traffic-timeline")
    assert response.status_code == 200

def test_mark_feedback_endpoint_sets_label(client):
    conn = sqlite3.connect(app_module.cfg["db_path"])
    conn.execute("INSERT INTO alerts (src_ip, dst_ip, action, score) VALUES (?, ?, ?, ?)",
                 ("9.9.9.9", "1.1.1.1", "BLOCK", -0.1))
    conn.commit()
    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    response = client.post(f"/api/alerts/{alert_id}/feedback", json={"label": "false_positive"})
    assert response.status_code == 200

def test_mark_feedback_rejects_invalid_label(client):
    response = client.post("/api/alerts/1/feedback", json={"label": "not_a_real_label"})
    assert response.status_code == 400

def test_mark_feedback_on_nonexistent_alert_returns_404(client):
    response = client.post("/api/alerts/9999/feedback", json={"label": "false_positive"})
    assert response.status_code == 404
